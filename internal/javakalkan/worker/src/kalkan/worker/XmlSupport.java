package kalkan.worker;

// Optional XML implementation is loaded only when its dependencies are supplied.
interface XmlSupport {
    byte[][] dispatch(int opcode, byte[][] args) throws Exception;
}
