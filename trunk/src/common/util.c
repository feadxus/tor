/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include "../or/or.h"
#include "../or/tree.h"

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif

/* used by inet_addr, not defined on solaris anywhere!? */
#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

/* in-line the strl functions */
#ifndef HAVE_STRLCPY
#include "strlcpy.c"
#endif
#ifndef HAVE_STRLCAT
#include "strlcat.c"
#endif

/*
 *    Memory wrappers
 */

void *tor_malloc(size_t size) {
  void *result;

  result = malloc(size);

  if(!result) {
    log_fn(LOG_ERR, "Out of memory. Dying.");
    exit(1);
  }
//  memset(result,'X',size); /* deadbeef to encourage bugs */
  return result;
}

void *tor_malloc_zero(size_t size) {
  void *result = tor_malloc(size);
  memset(result, 0, size);
  return result;
}

void *tor_realloc(void *ptr, size_t size) {
  void *result;

  result = realloc(ptr, size);
  if (!result) {
    log_fn(LOG_ERR, "Out of memory. Dying.");
    exit(1);
  }
  return result;
}

char *tor_strdup(const char *s) {
  char *dup;
  assert(s);

  dup = strdup(s);
  if(!dup) {
    log_fn(LOG_ERR,"Out of memory. Dying.");
    exit(1);
  }
  return dup;
}

char *tor_strndup(const char *s, size_t n) {
  char *dup;
  assert(s);
  dup = tor_malloc(n+1);
  strncpy(dup, s, n);
  dup[n] = 0;
  return dup;
}

/* Convert s to lowercase. */
void tor_strlower(char *s)
{
  while (*s) {
    *s = tolower(*s);
    ++s;
  }
}

#ifndef UNALIGNED_INT_ACCESS_OK
uint16_t get_uint16(char *cp)
{
  uint16_t v;
  memcpy(&v,cp,2);
  return v;
}
uint32_t get_uint32(char *cp)
{
  uint32_t v;
  memcpy(&v,cp,4);
  return v;
}
void set_uint16(char *cp, uint16_t v)
{
  memcpy(cp,&v,2);
}
void set_uint32(char *cp, uint32_t v)
{
  memcpy(cp,&v,4);
}
#endif

void hex_encode(const char *from, int fromlen, char *to)
{
  const unsigned char *fp = from;
  static const char TABLE[] = "0123456789abcdef";
  while (fromlen) {
    *to++ = TABLE[*fp >> 4];
    *to++ = TABLE[*fp & 7];
    ++fp;
  }
  *to = '\0';
}

/*
 * A simple smartlist interface to make an unordered list of acceptable
 * nodes and then choose a random one.
 * smartlist_create() mallocs the list, _free() frees the list,
 * _add() adds an element, _remove() removes an element if it's there,
 * _choose() returns a random element.
 */
#define SMARTLIST_DEFAULT_CAPACITY 32
smartlist_t *smartlist_create() {
  smartlist_t *sl = tor_malloc(sizeof(smartlist_t));
  sl->num_used = 0;
  sl->capacity = SMARTLIST_DEFAULT_CAPACITY;
  sl->list = tor_malloc(sizeof(void *) * sl->capacity);
  return sl;
}

void smartlist_free(smartlist_t *sl) {
  free(sl->list);
  free(sl);
}

void smartlist_set_capacity(smartlist_t *sl, int n) {
  if (sl->capacity != n && sl->num_used < n) {
    sl->capacity = n;
    sl->list = tor_realloc(sl->list, sizeof(void*)*sl->capacity);
  }
}

/* add element to the list, but only if there's room */
void smartlist_add(smartlist_t *sl, void *element) {
  if (sl->num_used >= sl->capacity) {
    sl->capacity *= 2;
    sl->list = tor_realloc(sl->list, sizeof(void*)*sl->capacity);
  }
  sl->list[sl->num_used++] = element;
}

void smartlist_remove(smartlist_t *sl, void *element) {
  int i;
  if(element == NULL)
    return;
  for(i=0; i < sl->num_used; i++)
    if(sl->list[i] == element) {
      sl->list[i] = sl->list[--sl->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
}

int smartlist_isin(smartlist_t *sl, void *element) {
  int i;
  for(i=0; i < sl->num_used; i++)
    if(sl->list[i] == element)
      return 1;
  return 0;
}

int smartlist_overlap(smartlist_t *sl1, smartlist_t *sl2) {
  int i;
  for(i=0; i < sl2->num_used; i++)
    if(smartlist_isin(sl1, sl2->list[i]))
      return 1;
  return 0;
}

/* remove elements of sl1 that aren't in sl2 */
void smartlist_intersect(smartlist_t *sl1, smartlist_t *sl2) {
  int i;
  for(i=0; i < sl1->num_used; i++)
    if(!smartlist_isin(sl2, sl1->list[i])) {
      sl1->list[i] = sl1->list[--sl1->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
}

/* remove all elements of sl2 from sl1 */
void smartlist_subtract(smartlist_t *sl1, smartlist_t *sl2) {
  int i;
  for(i=0; i < sl2->num_used; i++)
    smartlist_remove(sl1, sl2->list[i]);
}

void *smartlist_choose(smartlist_t *sl) {
  if(sl->num_used)
    return sl->list[crypto_pseudo_rand_int(sl->num_used)];
  return NULL; /* no elements to choose from */
}

/*
 * Splay-tree implementation of string-to-void* map
 */
struct strmap_entry_t {
  SPLAY_ENTRY(strmap_entry_t) node;
  char *key;
  void *val;
};

struct strmap_t {
  SPLAY_HEAD(strmap_tree, strmap_entry_t) head;
};

static int compare_strmap_entries(struct strmap_entry_t *a,
				 struct strmap_entry_t *b)
{
  return strcmp(a->key, b->key);
}

SPLAY_PROTOTYPE(strmap_tree, strmap_entry_t, node, compare_strmap_entries);
SPLAY_GENERATE(strmap_tree, strmap_entry_t, node, compare_strmap_entries);

/* Create a new empty map from strings to void*'s.
 */
strmap_t* strmap_new(void)
{
  strmap_t *result;
  result = tor_malloc(sizeof(strmap_t));
  SPLAY_INIT(&result->head);
  return result;
}

/* Set the current value for <key> with <val>.  Returns the previous
 * value for <key> if one was set, or NULL if one was not.
 *
 * This function makes a copy of 'key' if necessary, but not of 'val'.
 */
void* strmap_set(strmap_t *map, const char *key, void *val)
{
  strmap_entry_t *resolve;
  strmap_entry_t search;
  void *oldval;
  assert(map && key && val);
  search.key = (char*)key;
  resolve = SPLAY_FIND(strmap_tree, &map->head, &search);
  if (resolve) {
    oldval = resolve->val;
    resolve->val = val;
    return oldval;
  } else {
    resolve = tor_malloc_zero(sizeof(strmap_entry_t));
    resolve->key = tor_strdup(key);
    resolve->val = val;
    SPLAY_INSERT(strmap_tree, &map->head, resolve);
    return NULL;
  }
}

/* Return the current value associated with <key>, or NULL if no
 * value is set.
 */
void* strmap_get(strmap_t *map, const char *key)
{
  strmap_entry_t *resolve;
  strmap_entry_t search;
  assert(map && key);
  search.key = (char*)key;
  resolve = SPLAY_FIND(strmap_tree, &map->head, &search);
  if (resolve) {
    return resolve->val;
  } else {
    return NULL;
  }
}

/* Remove the value currently associated with <key> from the map.
 * Return the value if one was set, or NULL if there was no entry for
 * <key>.
 *
 * Note: you must free any storage associated with the returned value.
 */
void* strmap_remove(strmap_t *map, const char *key)
{
  strmap_entry_t *resolve;
  strmap_entry_t search;
  void *oldval;
  assert(map && key);
  search.key = (char*)key;
  resolve = SPLAY_FIND(strmap_tree, &map->head, &search);
  if (resolve) {
    oldval = resolve->val;
    SPLAY_REMOVE(strmap_tree, &map->head, resolve);
    tor_free(resolve->key);
    tor_free(resolve);
    return oldval;
  } else {
    return NULL;
  }
}

/* Same as strmap_set, but first converts <key> to lowercase. */
void* strmap_set_lc(strmap_t *map, const char *key, void *val)
{
  /* We could be a little faster by using strcasecmp instead, and a separate
   * type, but I don't think it matters. */
  void *v;
  char *lc_key = tor_strdup(key);
  tor_strlower(lc_key);
  v = strmap_set(map,lc_key,val);
  tor_free(lc_key);
  return v;
}
/* Same as strmap_get, but first converts <key> to lowercase. */
void* strmap_get_lc(strmap_t *map, const char *key)
{
  void *v;
  char *lc_key = tor_strdup(key);
  tor_strlower(lc_key);
  v = strmap_get(map,lc_key);
  tor_free(lc_key);
  return v;
}
/* Same as strmap_remove, but first converts <key> to lowercase */
void* strmap_remove_lc(strmap_t *map, const char *key)
{
  void *v;
  char *lc_key = tor_strdup(key);
  tor_strlower(lc_key);
  v = strmap_remove(map,lc_key);
  tor_free(lc_key);
  return v;
}


/* Invoke fn() on every entry of the map, in order.  For every entry,
 * fn() is invoked with that entry's key, that entry's value, and the
 * value of <data> supplied to strmap_foreach.  fn() must return a new
 * (possibly unmodified) value for each entry: if fn() returns NULL, the
 * entry is removed.
 *
 * Example:
 *   static void* upcase_and_remove_empty_vals(const char *key, void *val,
 *                                             void* data) {
 *     char *cp = (char*)val;
 *     if (!*cp) {  // val is an empty string.
 *       free(val);
 *       return NULL;
 *     } else {
 *       for (; *cp; cp++)
 *         *cp = toupper(*cp);
 *       }
 *       return val;
 *     }
 *   }
 *
 *   ...
 *
 *   strmap_foreach(map, upcase_and_remove_empty_vals, NULL);
 */
void strmap_foreach(strmap_t *map,
		    void* (*fn)(const char *key, void *val, void *data),
		    void *data)
{
  strmap_entry_t *ptr, *next;
  assert(map && fn);
  for (ptr = SPLAY_MIN(strmap_tree, &map->head); ptr != NULL; ptr = next) {
    /* This remove-in-place usage is specifically blessed in tree(3). */
    next = SPLAY_NEXT(strmap_tree, &map->head, ptr);
    ptr->val = fn(ptr->key, ptr->val, data);
    if (!ptr->val) {
      SPLAY_REMOVE(strmap_tree, &map->head, ptr);
      tor_free(ptr->key);
      tor_free(ptr);
    }
  }
}

/* return an 'iterator' pointer to the front of a map.
 *
 * Iterator example:
 *
 * // uppercase values in "map", removing empty values.
 *
 * strmap_iter_t *iter;
 * const char *key;
 * void *val;
 * char *cp;
 *
 * for (iter = strmap_iter_init(map); !strmap_iter_done(iter); ) {
 *    strmap_iter_get(iter, &key, &val);
 *    cp = (char*)val;
 *    if (!*cp) {
 *       iter = strmap_iter_next_rmv(iter);
 *       free(val);
 *    } else {
 *       for(;*cp;cp++) *cp = toupper(*cp);
 *       iter = strmap_iter_next(iter);
 *    }
 * }
 *
 */
strmap_iter_t *strmap_iter_init(strmap_t *map)
{
  assert(map);
  return SPLAY_MIN(strmap_tree, &map->head);
}
/* Advance the iterator 'iter' for map a single step to the next entry.
 */
strmap_iter_t *strmap_iter_next(strmap_t *map, strmap_iter_t *iter)
{
  assert(map && iter);
  return SPLAY_NEXT(strmap_tree, &map->head, iter);
}
/* Advance the iterator 'iter' a single step to the next entry, removing
 * the current entry.
 */
strmap_iter_t *strmap_iter_next_rmv(strmap_t *map, strmap_iter_t *iter)
{
  strmap_iter_t *next;
  assert(map && iter);
  next = SPLAY_NEXT(strmap_tree, &map->head, iter);
  SPLAY_REMOVE(strmap_tree, &map->head, iter);
  tor_free(iter->key);
  tor_free(iter);
  return next;
}
/* Set *keyp and *valp to the current entry pointed to by iter.
 */
void strmap_iter_get(strmap_iter_t *iter, const char **keyp, void **valp)
{
  assert(iter && keyp && valp);
  *keyp = iter->key;
  *valp = iter->val;
}
/* Return true iff iter has advanced past the last entry of map.
 */
int strmap_iter_done(strmap_iter_t *iter)
{
  return iter == NULL;
}
/* Remove all entries from <map>, and deallocate storage for those entries.
 * If free_val is provided, it is invoked on every value in <map>.
 */
void strmap_free(strmap_t *map, void (*free_val)(void*))
{
  strmap_entry_t *ent, *next;
  for (ent = SPLAY_MIN(strmap_tree, &map->head); ent != NULL; ent = next) {
    next = SPLAY_NEXT(strmap_tree, &map->head, ent);
    SPLAY_REMOVE(strmap_tree, &map->head, ent);
    tor_free(ent->key);
    if (free_val)
      tor_free(ent->val);
  }
  assert(SPLAY_EMPTY(&map->head));
  tor_free(map);
}

/*
 *    String manipulation
 */

/* return the first char of s that is not whitespace and not a comment */
const char *eat_whitespace(const char *s) {
  assert(s);

  while(isspace((int)*s) || *s == '#') {
    while(isspace((int)*s))
      s++;
    if(*s == '#') { /* read to a \n or \0 */
      while(*s && *s != '\n')
        s++;
      if(!*s)
        return s;
    }
  }
  return s;
}

const char *eat_whitespace_no_nl(const char *s) {
  while(*s == ' ' || *s == '\t')
    ++s;
  return s;
}

/* return the first char of s that is whitespace or '#' or '\0 */
const char *find_whitespace(const char *s) {
  assert(s);

  while(*s && !isspace((int)*s) && *s != '#')
    s++;

  return s;
}

/*
 *    Time
 */

void tor_gettimeofday(struct timeval *timeval) {
#ifdef HAVE_GETTIMEOFDAY
  if (gettimeofday(timeval, NULL)) {
    log_fn(LOG_ERR, "gettimeofday failed.");
    /* If gettimeofday dies, we have either given a bad timezone (we didn't),
       or segfaulted.*/
    exit(1);
  }
#elif defined(HAVE_FTIME)
  ftime(timeval);
#else
#error "No way to get time."
#endif
  return;
}

long
tv_udiff(struct timeval *start, struct timeval *end)
{
  long udiff;
  long secdiff = end->tv_sec - start->tv_sec;

  if (secdiff+1 > LONG_MAX/1000000) {
    log_fn(LOG_WARN, "comparing times too far apart.");
    return LONG_MAX;
  }

  udiff = secdiff*1000000L + (end->tv_usec - start->tv_usec);
  if(udiff < 0) {
    log_fn(LOG_INFO, "start (%ld.%ld) is after end (%ld.%ld). Returning 0.",
           (long)start->tv_sec, (long)start->tv_usec, (long)end->tv_sec, (long)end->tv_usec);
    return 0;
  }
  return udiff;
}

int tv_cmp(struct timeval *a, struct timeval *b) {
  if (a->tv_sec > b->tv_sec)
    return 1;
  if (a->tv_sec < b->tv_sec)
    return -1;
  if (a->tv_usec > b->tv_usec)
    return 1;
  if (a->tv_usec < b->tv_usec)
    return -1;
  return 0;
}

void tv_add(struct timeval *a, struct timeval *b) {
  a->tv_usec += b->tv_usec;
  a->tv_sec += b->tv_sec + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}

void tv_addms(struct timeval *a, long ms) {
  a->tv_usec += (ms * 1000) % 1000000;
  a->tv_sec += ((ms * 1000) / 1000000) + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}


#define IS_LEAPYEAR(y) (!(y % 4) && ((y % 100) || !(y % 400)))
static int n_leapdays(int y1, int y2) {
  --y1;
  --y2;
  return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}
static const int days_per_month[] =
  { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

time_t tor_timegm (struct tm *tm) {
  /* This is a pretty ironclad timegm implementation, snarfed from Python2.2.
   * It's way more brute-force than fiddling with tzset().
   */
  time_t ret;
  unsigned long year, days, hours, minutes;
  int i;
  year = tm->tm_year + 1900;
  assert(year >= 1970);
  assert(tm->tm_mon >= 0 && tm->tm_mon <= 11);
  days = 365 * (year-1970) + n_leapdays(1970,year);
  for (i = 0; i < tm->tm_mon; ++i)
    days += days_per_month[i];
  if (tm->tm_mon > 1 && IS_LEAPYEAR(year))
    ++days;
  days += tm->tm_mday - 1;
  hours = days*24 + tm->tm_hour;

  minutes = hours*60 + tm->tm_min;
  ret = minutes*60 + tm->tm_sec;
  return ret;
}

/*
 *   Low-level I/O.
 */

/* a wrapper for write(2) that makes sure to write all count bytes.
 * Only use if fd is a blocking fd. */
int write_all(int fd, const char *buf, size_t count, int isSocket) {
  size_t written = 0;
  int result;

  while(written != count) {
    if (isSocket)
      result = send(fd, buf+written, count-written, 0);
    else
      result = write(fd, buf+written, count-written);
    if(result<0)
      return -1;
    written += result;
  }
  return count;
}

/* a wrapper for read(2) that makes sure to read all count bytes.
 * Only use if fd is a blocking fd. */
int read_all(int fd, char *buf, size_t count, int isSocket) {
  size_t numread = 0;
  int result;

  while(numread != count) {
    if (isSocket) 
      result = recv(fd, buf+numread, count-numread, 0);
    else
      result = read(fd, buf+numread, count-numread);
    if(result<=0)
      return -1;
    numread += result;
  }
  return count;
}

void set_socket_nonblocking(int socket)
{
#ifdef MS_WINDOWS
  /* Yes means no and no means yes.  Do you not want to be nonblocking? */
  int nonblocking = 0;
  ioctlsocket(socket, FIONBIO, (unsigned long*) &nonblocking);
#else
  fcntl(socket, F_SETFL, O_NONBLOCK);
#endif
}

/*
 *   Process control
 */

/* Minimalist interface to run a void function in the background.  On
 * unix calls fork, on win32 calls beginthread.  Returns -1 on failure.
 * func should not return, but rather should call spawn_exit.
 */
int spawn_func(int (*func)(void *), void *data)
{
#ifdef MS_WINDOWS
  int rv;
  rv = _beginthread(func, 0, data);
  if (rv == (unsigned long) -1)
    return -1;
  return 0;
#else
  pid_t pid;
  pid = fork();
  if (pid<0)
    return -1;
  if (pid==0) {
    /* Child */
    func(data);
    assert(0); /* Should never reach here. */
    return 0; /* suppress "control-reaches-end-of-non-void" warning. */
  } else {
    /* Parent */
    return 0;
  }
#endif
}

void spawn_exit()
{
#ifdef MS_WINDOWS
  _endthread();
#else
  exit(0);
#endif
}


/*
 *   Windows compatibility.
 */
int
tor_socketpair(int family, int type, int protocol, int fd[2])
{
#ifdef HAVE_SOCKETPAIR_XXXX
    /* For testing purposes, we never fall back to real socketpairs. */
    return socketpair(family, type, protocol, fd);
#else
    int listener = -1;
    int connector = -1;
    int acceptor = -1;
    struct sockaddr_in listen_addr;
    struct sockaddr_in connect_addr;
    int size;

    if (protocol
#ifdef AF_UNIX
        || family != AF_UNIX
#endif
        ) {
#ifdef MS_WINDOWS
        errno = WSAEAFNOSUPPORT;
#else
        errno = EAFNOSUPPORT;
#endif
        return -1;
    }
    if (!fd) {
        errno = EINVAL;
        return -1;
    }

    listener = socket(AF_INET, type, 0);
    if (listener == -1)
      return -1;
    memset (&listen_addr, 0, sizeof (listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    listen_addr.sin_port = 0;   /* kernel choses port.  */
    if (bind(listener, (struct sockaddr *) &listen_addr, sizeof (listen_addr))
        == -1)
        goto tidy_up_and_fail;
    if (listen(listener, 1) == -1)
        goto tidy_up_and_fail;

    connector = socket(AF_INET, type, 0);
    if (connector == -1)
        goto tidy_up_and_fail;
    /* We want to find out the port number to connect to.  */
    size = sizeof (connect_addr);
    if (getsockname(listener, (struct sockaddr *) &connect_addr, &size) == -1)
        goto tidy_up_and_fail;
    if (size != sizeof (connect_addr))
        goto abort_tidy_up_and_fail;
    if (connect(connector, (struct sockaddr *) &connect_addr,
                sizeof (connect_addr)) == -1)
        goto tidy_up_and_fail;

    size = sizeof (listen_addr);
    acceptor = accept(listener, (struct sockaddr *) &listen_addr, &size);
    if (acceptor == -1)
        goto tidy_up_and_fail;
    if (size != sizeof(listen_addr))
        goto abort_tidy_up_and_fail;
    close(listener);
    /* Now check we are talking to ourself by matching port and host on the
       two sockets.  */
    if (getsockname(connector, (struct sockaddr *) &connect_addr, &size) == -1)
        goto tidy_up_and_fail;
    if (size != sizeof (connect_addr)
        || listen_addr.sin_family != connect_addr.sin_family
        || listen_addr.sin_addr.s_addr != connect_addr.sin_addr.s_addr
        || listen_addr.sin_port != connect_addr.sin_port) {
        goto abort_tidy_up_and_fail;
    }
    fd[0] = connector;
    fd[1] = acceptor;
    return 0;

  abort_tidy_up_and_fail:
#ifdef MS_WINDOWS
  errno = WSAECONNABORTED;
#else
  errno = ECONNABORTED; /* I hope this is portable and appropriate.  */
#endif
  tidy_up_and_fail:
    {
        int save_errno = errno;
        if (listener != -1)
            close(listener);
        if (connector != -1)
            close(connector);
        if (acceptor != -1)
            close(acceptor);
        errno = save_errno;
        return -1;
    }
#endif
}

#ifdef MS_WINDOWS
int correct_socket_errno(int s)
{
  int optval, optvallen=sizeof(optval);
  assert(errno == WSAEWOULDBLOCK);
  if (getsockopt(s, SOL_SOCKET, SO_ERROR, (void*)&optval, &optvallen))
    return errno;
  if (optval)
    return optval;
  return WSAEWOULDBLOCK;
}
#endif

/*
 *    Filesystem operations.
 */

/* Return FN_ERROR if filename can't be read, FN_NOENT if it doesn't
 * exist, FN_FILE if it is a regular file, or FN_DIR if it's a
 * directory. */
file_status_t file_status(const char *fname)
{
  struct stat st;
  if (stat(fname, &st)) {
    if (errno == ENOENT) {
      return FN_NOENT;
    }
    return FN_ERROR;
  }
  if (st.st_mode & S_IFDIR)
    return FN_DIR;
  else if (st.st_mode & S_IFREG)
    return FN_FILE;
  else
    return FN_ERROR;
}

/* Check whether dirname exists and is private.  If yes returns
   0.  Else returns -1. */
int check_private_dir(const char *dirname, int create)
{
  int r;
  struct stat st;
  if (stat(dirname, &st)) {
    if (errno != ENOENT) {
      log(LOG_WARN, "Directory %s cannot be read: %s", dirname,
          strerror(errno));
      return -1;
    }
    if (!create) {
      log(LOG_WARN, "Directory %s does not exist.", dirname);
      return -1;
    }
    log(LOG_INFO, "Creating directory %s", dirname);
#ifdef MS_WINDOWS
    r = mkdir(dirname);
#else
    r = mkdir(dirname, 0700);
#endif
    if (r) {
      log(LOG_WARN, "Error creating directory %s: %s", dirname,
          strerror(errno));
      return -1;
    } else {
      return 0;
    }
  }
  if (!(st.st_mode & S_IFDIR)) {
    log(LOG_WARN, "%s is not a directory", dirname);
    return -1;
  }
#ifndef MS_WINDOWS
  if (st.st_uid != getuid()) {
    log(LOG_WARN, "%s is not owned by this UID (%d)", dirname, (int)getuid());
    return -1;
  }
  if (st.st_mode & 0077) {
    log(LOG_WARN, "Fixing permissions on directory %s", dirname);
    if (chmod(dirname, 0700)) {
      log(LOG_WARN, "Could not chmod directory %s: %s", dirname,
          strerror(errno));
      return -1;
    } else {
      return 0;
    }
  }
#endif
  return 0;
}

int
write_str_to_file(const char *fname, const char *str)
{
  char tempname[1024];
  int fd;
  FILE *file;
  if ((strlcpy(tempname,fname,1024) >= 1024) ||
      (strlcat(tempname,".tmp",1024) >= 1024)) {
    log(LOG_WARN, "Filename %s.tmp too long (>1024 chars)", fname);
    return -1;
  }
  if ((fd = open(tempname, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
    log(LOG_WARN, "Couldn't open %s for writing: %s", tempname,
        strerror(errno));
    return -1;
  }
  if (!(file = fdopen(fd, "w"))) {
    log(LOG_WARN, "Couldn't fdopen %s for writing: %s", tempname,
        strerror(errno));
    close(fd); return -1;
  }
  if (fputs(str,file) == EOF) {
    log(LOG_WARN, "Error writing to %s: %s", tempname, strerror(errno));
    fclose(file); return -1;
  }
  fclose(file);
  if (rename(tempname, fname)) {
    log(LOG_WARN, "Error replacing %s: %s", fname, strerror(errno));
    return -1;
  }
  return 0;
}

char *read_file_to_str(const char *filename) {
  int fd; /* router file */
  struct stat statbuf;
  char *string;

  assert(filename);

  if(strcspn(filename,CONFIG_LEGAL_FILENAME_CHARACTERS) != 0) {
    log_fn(LOG_WARN,"Filename %s contains illegal characters.",filename);
    return NULL;
  }

  if(stat(filename, &statbuf) < 0) {
    log_fn(LOG_INFO,"Could not stat %s.",filename);
    return NULL;
  }

  fd = open(filename,O_RDONLY,0);
  if (fd<0) {
    log_fn(LOG_WARN,"Could not open %s.",filename);
    return NULL;
  }

  string = tor_malloc(statbuf.st_size+1);

  if(read_all(fd,string,statbuf.st_size,0) != statbuf.st_size) {
    log_fn(LOG_WARN,"Couldn't read all %ld bytes of file '%s'.",
           (long)statbuf.st_size,filename);
    free(string);
    close(fd);
    return NULL;
  }
  close(fd);

  string[statbuf.st_size] = 0; /* null terminate it */
  return string;
}

/* read lines from f (no more than maxlen-1 bytes each) until we
 * get a non-whitespace line. If it isn't of the form "key value"
 * (value can have spaces), return -1.
 * Point *key to the first word in line, point *value * to the second.
 * Put a \0 at the end of key, remove everything at the end of value
 * that is whitespace or comment.
 * Return 1 if success, 0 if no more lines, -1 if error.
 */
int parse_line_from_file(char *line, int maxlen, FILE *f, char **key_out, char **value_out) {
  char *s, *key, *end, *value;

try_next_line:
  if(!fgets(line, maxlen, f)) {
    if(feof(f))
      return 0;
    return -1; /* real error */
  }

  if((s = strchr(line,'#'))) /* strip comments */
    *s = 0; /* stop the line there */

  /* remove end whitespace */
  s = strchr(line, 0); /* now we're at the null */
  do {
    *s = 0;
    s--;
  } while (s >= line && isspace((int)*s));

  key = line;
  while(isspace((int)*key))
    key++;
  if(*key == 0)
    goto try_next_line; /* this line has nothing on it */
  end = key;
  while(*end && !isspace((int)*end))
    end++;
  value = end;
  while(*value && isspace((int)*value))
    value++;

  if(!*end || !*value) { /* only a key on this line. no value. */
    *end = 0;
    log_fn(LOG_WARN,"Line has keyword '%s' but no value. Failing.",key);
    return -1;
  }
  *end = 0; /* null it out */

  log_fn(LOG_DEBUG,"got keyword '%s', value '%s'", key, value);
  *key_out = key, *value_out = value;
  return 1;
}

int is_internal_IP(uint32_t ip) {

  if (((ip & 0xff000000) == 0x0a000000) || /*       10/8 */
      ((ip & 0xff000000) == 0x00000000) || /*        0/8 */
      ((ip & 0xff000000) == 0x7f000000) || /*      127/8 */
      ((ip & 0xffff0000) == 0xa9fe0000) || /* 169.254/16 */
      ((ip & 0xfff00000) == 0xac100000) || /*  172.16/12 */
      ((ip & 0xffff0000) == 0xc0a80000))   /* 192.168/16 */
    return 1;
  return 0;
}

static char uname_result[256];
static int uname_result_is_set = 0;

const char *
get_uname(void)
{
#ifdef HAVE_UNAME
  struct utsname u;
#endif
  if (!uname_result_is_set) {
#ifdef HAVE_UNAME
    if (uname(&u) != -1) {
      /* (linux says 0 is success, solaris says 1 is success) */
      snprintf(uname_result, 255, "%s %s %s",
               u.sysname, u.nodename, u.machine);
      uname_result[255] = '\0';
    } else
#endif
      {
        strcpy(uname_result, "Unknown platform");
      }
    uname_result_is_set = 1;
  }
  return uname_result;
}

#ifndef MS_WINDOWS
/* Based on code contributed by christian grothoff */
static int start_daemon_called = 0;
static int finish_daemon_called = 0;
static int daemon_filedes[2];
void start_daemon(char *desired_cwd)
{
  pid_t pid;

  if (start_daemon_called)
    return;
  start_daemon_called = 1;

  if(!desired_cwd)
    desired_cwd = "/";
   /* Don't hold the wrong FS mounted */
  if (chdir(desired_cwd) < 0) {
    log_fn(LOG_ERR,"chdir to %s failed. Exiting.",desired_cwd);
    exit(1);
  }

  pipe(daemon_filedes);
  pid = fork();
  if (pid < 0) {
    log_fn(LOG_ERR,"fork failed. Exiting.");
    exit(1);
  }
  if (pid) {  /* Parent */
    int ok;
    char c;

    close(daemon_filedes[1]); /* we only read */
    ok = -1;
    while (0 < read(daemon_filedes[0], &c, sizeof(char))) {
      if (c == '.')
        ok = 1;
    }
    fflush(stdout);
    if (ok == 1)
      exit(0);
    else
      exit(1); /* child reported error */
  } else { /* Child */
    close(daemon_filedes[0]); /* we only write */

    pid = setsid(); /* Detach from controlling terminal */
    /*
     * Fork one more time, so the parent (the session group leader) can exit. 
     * This means that we, as a non-session group leader, can never regain a
     * controlling terminal.   This part is recommended by Stevens's
     * _Advanced Programming in the Unix Environment_.
     */
    if (fork() != 0) {
      exit(0);
    }
    return;
  }
}

void finish_daemon(void)
{
  int nullfd;
  char c = '.';
  if (finish_daemon_called)
    return;
  if (!start_daemon_called)
    start_daemon(NULL);
  finish_daemon_called = 1;

  nullfd = open("/dev/null",
                O_CREAT | O_RDWR | O_APPEND);
  if (nullfd < 0) {
    log_fn(LOG_ERR,"/dev/null can't be opened. Exiting.");
    exit(1);
  }
  /* close fds linking to invoking terminal, but
   * close usual incoming fds, but redirect them somewhere
   * useful so the fds don't get reallocated elsewhere.
   */
  if (dup2(nullfd,0) < 0 ||
      dup2(nullfd,1) < 0 ||
      dup2(nullfd,2) < 0) {
    log_fn(LOG_ERR,"dup2 failed. Exiting.");
    exit(1);
  }
  write(daemon_filedes[1], &c, sizeof(char)); /* signal success */
  close(daemon_filedes[1]);
}
#else
/* defined(MS_WINDOWS) */
void start_daemon(char *cp) {}
void finish_daemon(void) {}
#endif

void write_pidfile(char *filename) {
#ifndef MS_WINDOWS
  FILE *pidfile;

  if ((pidfile = fopen(filename, "w")) == NULL) {
    log_fn(LOG_WARN, "unable to open %s for writing: %s", filename,
           strerror(errno));
  } else {
    fprintf(pidfile, "%d", (int)getpid());
    fclose(pidfile);
  }
#endif
}

int switch_id(char *user, char *group) {
#ifndef MS_WINDOWS
  struct passwd *pw = NULL;
  struct group *gr = NULL;

  if (user) {
    pw = getpwnam(user);
    if (pw == NULL) {
      log_fn(LOG_ERR,"User '%s' not found.", user);
      return -1;
    }
  }

  /* switch the group first, while we still have the privileges to do so */
  if (group) {
    gr = getgrnam(group);
    if (gr == NULL) {
      log_fn(LOG_ERR,"Group '%s' not found.", group);
      return -1;
    }

    if (setgid(gr->gr_gid) != 0) {
      log_fn(LOG_ERR,"Error setting GID: %s", strerror(errno));
      return -1;
    }
  } else if (user) {
    if (setgid(pw->pw_gid) != 0) {
      log_fn(LOG_ERR,"Error setting GID: %s", strerror(errno));
      return -1;
    }
  }

  /* now that the group is switched, we can switch users and lose
     privileges */
  if (user) {
    if (setuid(pw->pw_uid) != 0) {
      log_fn(LOG_ERR,"Error setting UID: %s", strerror(errno));
      return -1;
    }
  }

  return 0;
#endif

  log_fn(LOG_ERR,
         "User or group specified, but switching users is not supported.");

  return -1;
}

int tor_inet_aton(const char *c, struct in_addr* addr)
{
#ifdef HAVE_INET_ATON
  return inet_aton(c, addr);
#else
  uint32_t r;
  assert(c && addr);
  if (strcmp(c, "255.255.255.255") == 0) {
    addr->s_addr = 0xFFFFFFFFu;
    return 1;
  }
  r = inet_addr(c);
  if (r == INADDR_NONE)
    return 0;
  addr->s_addr = r;
  return 1;
#endif
}
