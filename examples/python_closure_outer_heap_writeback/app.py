from repo import Box, load, alt

def outer(cmd):
    holder = Box()
    holder.inner = Box()
    holder.inner.cb = load

    def patch():
        holder.inner.cb = alt

    patch()
    return holder.inner.cb(cmd)
