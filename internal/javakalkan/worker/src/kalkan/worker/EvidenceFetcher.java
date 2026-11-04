package kalkan.worker;

/** Revocation and timestamp I/O is supplied by the host's controlled transport. */
interface EvidenceFetcher {
    byte[] fetch(String method, String url, byte[] body) throws Exception;
}
