struct Left {};
struct Right {};
struct Multi : Left, Right {};
struct Destination {};

Destination *convert(Multi *value) {
    return reinterpret_cast<Destination *>(value);
}
