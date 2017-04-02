#include <sys/stat.h>

#include "sm-index.h"
#include "sm-log-file.h"
#include "sm-rep.h"
#include "../benchmarks/ndb_wrapper.h"

namespace rep {
// A daemon that runs on the primary for bringing up backups by shipping
// the latest chkpt (if any) + the log that follows (if any).
void primary_daemon_tcp() {
  ALWAYS_ASSERT(logmgr);
  tcp::server_context primary_tcp_ctx(config::primary_port, config::num_backups);

wait_for_backup:
  int backup_sockfd = primary_tcp_ctx.expect_client();

  // Got a new backup, send out the latest chkpt (if any)
  // Scan the whole log dir, and send chkpt (if any) + the log that follows,
  // or all the logs if a chkpt doesn't exist.
  int chkpt_fd = -1;
  LSN chkpt_start_lsn = INVALID_LSN;
  backup_start_metadata* md = prepare_start_metadata(chkpt_fd, chkpt_start_lsn);
  auto sent_bytes = send(backup_sockfd, md, md->size(), 0);
  ALWAYS_ASSERT(sent_bytes == md->size());

  // TODO(tzwang): support log-only bootstrap
  ALWAYS_ASSERT(chkpt_fd != -1);
  if(chkpt_fd != -1) {
    off_t offset = 0;
    while(md->chkpt_size > 0) {
      sent_bytes = sendfile(backup_sockfd, chkpt_fd, &offset, md->chkpt_size);
      ALWAYS_ASSERT(sent_bytes);
      md->chkpt_size -= sent_bytes;
    }
    os_close(chkpt_fd);
  }

  // Now send the log after chkpt
  send_log_files_after_tcp(backup_sockfd, md, chkpt_start_lsn);

  // Wait for the backup to notify me that it persisted the logs
  tcp::expect_ack(backup_sockfd);

  // Surely backup is alive and ready after we got ack'ed, make it visible to the shipping thread
  backup_sockfds_mutex.lock();
  backup_sockfds.push_back(backup_sockfd);
  ++config::num_active_backups;
  backup_sockfds_mutex.unlock();
  goto wait_for_backup;
}

void send_log_files_after_tcp(int backup_fd, backup_start_metadata* md, LSN chkpt_start) {
  dirent_iterator dir(config::log_dir.c_str());
  int dfd = dir.dup();
  for(uint32_t i = 0; i < md->num_log_files; ++i) {
    uint32_t segnum = 0;
    uint64_t start_offset = 0, end_offset = 0; 
    char canary_unused;
    backup_start_metadata::log_segment* ls = md->get_log_segment(i);
    int n = sscanf(ls->file_name.buf, SEGMENT_FILE_NAME_FMT "%c",
                   &segnum, &start_offset, &end_offset, &canary_unused);
    ALWAYS_ASSERT(n == 3);
    uint32_t to_send = ls->size;
    if(to_send) {
      // Ship only the part after chkpt start
      auto* seg = logmgr->get_offset_segment(start_offset);
      off_t file_off = start_offset - seg->start_offset;
      int log_fd = os_openat(dfd, ls->file_name.buf, O_RDONLY);
      lseek(log_fd, file_off, SEEK_SET);
      while(to_send) {
        auto sent_bytes = sendfile(backup_fd, log_fd, &file_off, to_send);
        ALWAYS_ASSERT(sent_bytes);
      }
      os_close(log_fd);
    }
  }
}

void start_as_backup_tcp() {
  memset(logbuf_partition_bounds, 0, sizeof(uint64_t) * kMaxLogBufferPartitions);
  ALWAYS_ASSERT(config::is_backup_srv());

  LOG(INFO) << "[Backup] Primary: " << config::primary_srv << ":" << config::primary_port;
  tcp::client_context *cctx = new tcp::client_context(config::primary_srv, config::primary_port);

  // Expect the primary to send metadata, the header first
  const int kNumPreAllocFiles = 10;
  backup_start_metadata* md = allocate_backup_start_metadata(kNumPreAllocFiles);
  tcp::receive(cctx->server_sockfd, (char*)md, sizeof(*md));
  LOG(INFO) << "[Backup] Receive chkpt " << md->chkpt_marker << " " << md->chkpt_size << " bytes";
  if(md->num_log_files > kNumPreAllocFiles) {
    auto* d = md;
    md = allocate_backup_start_metadata(d->num_log_files);
    memcpy(md, d, sizeof(*d));
    free(d);
  }
  md->persist_marker_files();

  // Get log file names
  if(md->num_log_files > 0) {
    uint64_t s = md->size() - sizeof(*md);
    tcp::receive(cctx->server_sockfd, (char*)&md->segments[0], s);
  }

  static const uint64_t kBufSize = 512 * 1024 * 1024;
  static char buf[kBufSize];
  if(md->chkpt_size > 0) {
    dirent_iterator dir(config::log_dir.c_str());
    int dfd = dir.dup();
    char canary_unused;
    uint64_t chkpt_start = 0, chkpt_end_unused;
    int n = sscanf(md->chkpt_marker, CHKPT_FILE_NAME_FMT "%c",
                   &chkpt_start, &chkpt_end_unused, &canary_unused);
    static char chkpt_fname[CHKPT_DATA_FILE_NAME_BUFSZ];
    n = os_snprintf(chkpt_fname, sizeof(chkpt_fname),
                           CHKPT_DATA_FILE_NAME_FMT, chkpt_start);
    int chkpt_fd = os_openat(dfd, chkpt_fname, O_CREAT|O_WRONLY);
    LOG(INFO) << "[Backup] Checkpoint " << chkpt_fname;

    while(md->chkpt_size > 0) {
      uint64_t received_bytes =
        recv(cctx->server_sockfd, buf, std::min(kBufSize, md->chkpt_size), 0);
      md->chkpt_size -= received_bytes;
      os_write(chkpt_fd, buf, received_bytes);
    }
    os_fsync(chkpt_fd);
    os_close(chkpt_fd);
  }

  LOG(INFO) << "[Backup] Received checkpoint file.";

  // Now receive the log files
  dirent_iterator dir(config::log_dir.c_str());
  int dfd = dir.dup();
  for(uint64_t i = 0; i < md->num_log_files; ++i) {
    backup_start_metadata::log_segment* ls = md->get_log_segment(i);
    uint64_t file_size = ls->size;
    int log_fd = os_openat(dfd, ls->file_name.buf, O_CREAT|O_WRONLY);
    ALWAYS_ASSERT(log_fd > 0);
    while(file_size > 0) {
      uint64_t received_bytes = recv(cctx->server_sockfd, buf, std::min(file_size, kBufSize), 0);
      file_size -= received_bytes;
      os_write(log_fd, buf, received_bytes);
    }
    os_fsync(log_fd);
    os_close(log_fd);
  }

  logmgr = sm_log::new_log(config::recover_functor, nullptr);
  sm_oid_mgr::create();

  if(recover_first) {
    ALWAYS_ASSERT(oidmgr);
    logmgr->recover();
  }

  // Done with receiving files and they should all be persisted, now ack the primary
  tcp::send_ack(cctx->server_sockfd);
  LOG(INFO) << "[Backup] Received log file.";
  std::thread t(backup_daemon_tcp, cctx);
  t.detach();

  if(!recover_first) {
    // Now we proceed to recovery
    ALWAYS_ASSERT(oidmgr);
    logmgr->recover();
  }
}

// Send the log buffer to backups
void primary_ship_log_buffer_tcp(int backup_sockfd, const char* buf, uint32_t size) {
  ALWAYS_ASSERT(size);
  size_t nbytes = send(backup_sockfd, (char *)&size, sizeof(uint32_t), 0);
  THROW_IF(nbytes != sizeof(uint32_t), log_file_error, "Incomplete log shipping (header)");
  nbytes = send(backup_sockfd, buf, size, 0);
  THROW_IF(nbytes != size, log_file_error, "Incomplete log shipping (data)");
  // XXX(tzwang): do this in flush()?
  tcp::expect_ack(backup_sockfd);
}

void backup_daemon_tcp(tcp::client_context *cctx) {
  rcu_register();
  rcu_enter();
  DEFER(rcu_exit());
  DEFER(rcu_deregister());
  DEFER(delete cctx);

  // Listen to incoming log records from the primary
  uint32_t size = 0;
  // Wait for the main thread to create logmgr - it might run slower than me
  while (not volatile_read(logmgr)) {}
  auto* logbuf = logmgr->get_logbuf();

  // Now safe to start the redo daemon with a valid durable_flushed_lsn
  //if (not config::log_ship_sync_redo) {
  //  std::thread rt(redo_daemon);
  //  rt.detach();
  //}

  while (1) {
    // expect an integer indicating data size
    tcp::receive(cctx->server_sockfd, (char *)&size, sizeof(size));
    ALWAYS_ASSERT(size);

    // prepare segment if needed
    LSN start_lsn =  logmgr->durable_flushed_lsn();
    uint64_t end_lsn_offset = start_lsn.offset() + size;
    segment_id *sid = logmgr->assign_segment(start_lsn.offset(), end_lsn_offset);
    ALWAYS_ASSERT(sid);
    LSN end_lsn = sid->make_lsn(end_lsn_offset);
    ASSERT(end_lsn_offset == end_lsn.offset());

    // expect the real log data
    //std::cout << "[Backup] Will receive " << size << " bytes\n";
    char *buf = logbuf->write_buf(sid->buf_offset(start_lsn), size);
    ALWAYS_ASSERT(buf);   // XXX: consider different log buffer sizes than the primary's later
    tcp::receive(cctx->server_sockfd, buf, size);
    std::cout << "[Backup] Recieved " << size << " bytes ("
      << std::hex << start_lsn.offset() << "-" << end_lsn.offset() << std::dec << ")\n";

    // now got the batch of log records, persist them
    if (config::nvram_log_buffer) {
      logmgr->persist_nvram_log_buffer(*logbuf, end_lsn_offset);
    } else {
      logmgr->flush_log_buffer(*logbuf, end_lsn_offset, true);
      ASSERT(logmgr->durable_flushed_lsn() == end_lsn);
    }

    tcp::send_ack(cctx->server_sockfd);

    if (config::log_ship_sync_redo) {
      logmgr->redo_log(start_lsn, end_lsn);
      printf("[Backup] Rolled forward log %lx-%lx\n", start_lsn.offset(), end_lsn_offset);
    }
    if (config::nvram_log_buffer)
      logmgr->flush_log_buffer(*logbuf, end_lsn_offset, true);
  }
}

}  // namespace rep
