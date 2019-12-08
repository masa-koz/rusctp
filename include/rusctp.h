#ifndef RUSCTP_H
#define RUSCTP_H

#if defined(__cplusplus)
extern "C"
{
#endif
#include <stdint.h>

    typedef enum rusctp_loglevel
    {
        /// A level lower than all log levels.
        RUSCTP_LOGLEVEL_OFF = 0,
        /// Corresponds to the `Error` log level.
        RUSCTP_LOGLEVEL_ERROR = 1,
        /// Corresponds to the `Warn` log level.
        RUSCTP_LOGLEVEL_WARN = 2,
        /// Corresponds to the `Info` log level.
        RUSCTP_LOGLEVEL_INFO = 3,
        /// Corresponds to the `Debug` log level.
        RUSCTP_LOGLEVEL_DEBUG = 4,
        /// Corresponds to the `Trace` log level.
        RUSCTP_LOGLEVEL_TRACE = 5,
    } rusctp_loglevel;

    // Enables logging.
    int
    rusctp_enable_logging(void (*cb)(const char *line, void *argp),
                          void *argp, rusctp_loglevel max_level);
    // Returns a human readable string with the rusctp version number.
    const char *rusctp_version(void);

    // Parse sctp common header.
    int rusctp_header_info(uint8_t *rbuf, size_t rbuf_len, uint16_t *src_port, uint16_t *dst_port, uint32_t *vtag);

    // An SCTP association.
    typedef struct Association rusctp_assoc;

    rusctp_assoc *rusctp_accept(
        struct sockaddr *from_sa,
        size_t from_salen,
        uint8_t *rbuf,
        size_t *rbuf_len,
        uint8_t *sbuf,
        size_t sbuf_len,
        uint8_t *secret,
        size_t secret_len);

    void rusctp_assoc_free(rusctp_assoc *assoc);
#if defined(__cplusplus)
} // extern C
#endif

#endif