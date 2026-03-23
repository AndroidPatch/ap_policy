/*
 * Compatibility functions for Android/non-glibc systems
 *
 * reallocarray is a BSD/glibc extension that's not available on Android
 */

#include <stdlib.h>
#include <errno.h>

#ifndef HAVE_REALLOCARRAY

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
    /* Check for overflow */
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        errno = ENOMEM;
        return NULL;
    }
    return realloc(ptr, nmemb * size);
}

#endif
