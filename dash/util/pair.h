#ifndef UTIL_PAIR_H_
#define UTIL_PAIR_H_

#include <cstdlib>
#include <immintrin.h>

namespace dash {

typedef size_t Key_t;

/*variable length key*/
struct string_key{
    int length;
    char key[0];
};

} // namespace dash

#endif  // UTIL_PAIR_H_
