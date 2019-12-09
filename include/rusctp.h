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

    // A configutation for SCTP association.
    typedef struct IntialConfig rusctp_init_config;

    // Create a configuration
    rusctp_init_config *rusctp_config_new(uint16_t sh_local_port);

    // Set a secret key.
    int rusctp_config_set_secret_key(rusctp_init_config *config, uint8_t *secret, size_t secret_len);

    // Add a local addeess.
    int rusctp_config_add_laddr(rusctp_init_config *config, struct sockaddr *laddr_sa,
                                size_t laddr_salen);

    // Free a configuration.
    void rusctp_config_free(rusctp_init_config *config);

    // Parse an sctp common header.
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
        rusctp_init_config *config);

    void rusctp_assoc_free(rusctp_assoc *assoc);
#if defined(__cplusplus)
} // extern C
#endif

#endif