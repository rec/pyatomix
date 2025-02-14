#include <pybind11/pybind11.h>
#include <atomic>
#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)
namespace py = pybind11;
using namespace pybind11::literals;

class AtomicFlag {
public:
    AtomicFlag() { value.clear(std::memory_order_release); }
    AtomicFlag(bool init) {
        if (init) {
            value.test_and_set();
        } else {
            value.clear(std::memory_order_release);
        }
    }
    void clear() { value.clear(std::memory_order_release); }
    bool test_and_set() { return value.test_and_set(); }
    bool test() { return value.test(std::memory_order_acquire); }
    void wait(bool old) { value.wait(old, std::memory_order_acquire); }
    void notify_one() { value.notify_one(); }
    void notify_all() { value.notify_all(); }
    bool operator==(py::object other) const {
        return value.test(std::memory_order_acquire) == py::bool_(other);
    }
    bool operator!=(py::object other) const {
        return value.test(std::memory_order_acquire) != py::bool_(other);
    }
    py::tuple getstate() {
        return py::make_tuple(value.test());
    }
    void setstate(py::tuple state) {
        bool x = state[0].cast<bool>();
        if (x) {
            value.test_and_set();
        } else {
            value.clear(std::memory_order_release);
        }
    }
private:
    std::atomic_flag value = ATOMIC_FLAG_INIT;
};

template <typename Int>
class AtomicInt {
public:
    AtomicInt() : value(0) {}
    AtomicInt(Int value) : value(value) {}
    bool is_lock_free() { return value.is_lock_free(); }
    Int load() { return value.load(std::memory_order_acquire); }
    void store(Int new_val) { value.store(new_val, std::memory_order_release); }
    Int fetch_add(Int val) { return value.fetch_add(val, std::memory_order_acq_rel); }
    Int fetch_sub(Int val) { return value.fetch_sub(val, std::memory_order_acq_rel); }
    Int exchange(Int new_val) { return value.exchange(new_val, std::memory_order_acq_rel); }
    bool compare_exchange(Int expected_val, Int new_val) {
        return value.compare_exchange_strong(expected_val, new_val);
        }
    bool compare_exchange_weak(Int expected_val, Int new_val) {
        return value.compare_exchange_weak(expected_val, new_val);
        }
    bool operator==(Int other) const {
        return value == other;
    }
    bool operator!=(Int other) const {
        return value != other;
    }
    Int operator+(Int other) {
        return value.load(std::memory_order_acquire) + other;
    }
    AtomicInt* operator+=(Int other) {
        value += other;
        return this;
    }
    Int operator-(Int other) {
        return value.load(std::memory_order_acquire) + other;
    }
    AtomicInt* operator-=(Int other) {
        value -= other;
        return this;
    }
    Int rsub(Int other) {
        return other - value.load(std::memory_order_acquire);
    }
    Int operator*(Int other) {
        return value.load(std::memory_order_acquire) * other;
    }
    AtomicInt* operator*=(Int other) {
        value.exchange(value.load(std::memory_order_acquire) * other, std::memory_order_acq_rel);
        return this;
    }
    Int operator/(Int other) {
        return value.load(std::memory_order_acquire) / other;
    }
    AtomicInt* operator/=(Int other) {
        value.exchange(value.load(std::memory_order_acquire) / other, std::memory_order_acq_rel);
        return this;
    }
    Int rdiv(Int other) {
        return other / value.load(std::memory_order_acquire);
    }
    Int operator%(Int other) {
        return value.load(std::memory_order_acquire) % other;
    }
    AtomicInt* operator%=(Int other) {
        value.exchange(value.load(std::memory_order_acquire) % other, std::memory_order_acq_rel);
        return this;
    }
    Int rmod(Int other) {
        return other % value.load(std::memory_order_acquire);
    }
    Int operator&(Int other) {
        return value.load(std::memory_order_acquire) & other;
    }
    AtomicInt* operator&=(Int other) {
        value &= other;
        return this;
    }
    Int operator|(Int other) {
        return value.load(std::memory_order_acquire) | other;
    }
    AtomicInt* operator|=(Int other) {
        value |= other;
        return this;
    }
    Int operator^(Int other) {
        return value.load(std::memory_order_acquire) ^ other;
    }
    AtomicInt* operator^=(Int other) {
        value ^= other;
        return this;
    }
    bool lt(Int other) {
        return value.load(std::memory_order_acquire) < other;
    }
    bool le(Int other) {
        return value.load(std::memory_order_acquire) <= other;
    }
    bool gt(Int other) {
        return value.load(std::memory_order_acquire) > other;
    }
    bool ge(Int other) {
        return value.load(std::memory_order_acquire) >= other;
    }
    std::string str() {
        return std::to_string(value.load(std::memory_order_acquire));
    }
    py::tuple getstate() {
        return py::make_tuple(value.load(std::memory_order_acquire));
    }
    void setstate(py::tuple state) {
        Int x = state[0].cast<Int>();
        value.store(x);
    }

    static void classDef(::pybind11::module_ &m, const std::string& name) {
        py::class_<AtomicInt<int>>(m, name)
            .def(py::init<Int>())
            .def(py::init<>())
            .def("is_lock_free", &AtomicInt<Int>::is_lock_free)
            .def("load", &AtomicInt<Int>::load)
            .def("store", &AtomicInt<Int>::store)
            .def("fetch_add", &AtomicInt<Int>::fetch_add)
            .def("fetch_sub", &AtomicInt<Int>::fetch_sub)
            .def("exchange", &AtomicInt<Int>::exchange)
            .def("compare_exchange", &AtomicInt<Int>::compare_exchange)
            .def("compare_exchange_weak", &AtomicInt<Int>::compare_exchange_weak)
            .def("__eq__", &AtomicInt<Int>::operator==)
            .def("__neq__", &AtomicInt<Int>::operator!=)
            .def("__add__", &AtomicInt<Int>::operator+)
            .def("__iadd__", &AtomicInt<Int>::operator+=)
            .def("__sub__", &AtomicInt<Int>::operator-)
            .def("__isub__", &AtomicInt<Int>::operator-=)
            .def("__rsub__", &AtomicInt<Int>::rsub)
            .def("__mul__", &AtomicInt<Int>::operator*)
            .def("__imul__", &AtomicInt<Int>::operator*=)
            .def("__rmul__", &AtomicInt<Int>::operator*)
            .def("__truediv__", &AtomicInt<Int>::operator/)
            .def("__floordiv__", &AtomicInt<Int>::operator/)
            .def("__ifloordiv__", &AtomicInt<Int>::operator/=)
            .def("__itruediv__", &AtomicInt<Int>::operator/=)
            .def("__rfloordiv__", &AtomicInt<Int>::rdiv)
            .def("__rtruediv__", &AtomicInt<Int>::rdiv)
            .def("__mod__", &AtomicInt<Int>::operator%)
            .def("__imod__", &AtomicInt<Int>::operator%=)
            .def("__rmod__", &AtomicInt<Int>::rmod)
            .def("__and__", &AtomicInt<Int>::operator&)
            .def("__iand__", &AtomicInt<Int>::operator&=)
            .def("__rand__", &AtomicInt<Int>::operator&)
            .def("__or__", &AtomicInt<Int>::operator|)
            .def("__ior__", &AtomicInt<Int>::operator|=)
            .def("__ror__", &AtomicInt<Int>::operator|)
            .def("__xor__", &AtomicInt<Int>::operator^)
            .def("__ixor__", &AtomicInt<Int>::operator^=)
            .def("__rxor__", &AtomicInt<Int>::operator^)
            .def("__lt__", &AtomicInt<Int>::lt)
            .def("__le__", &AtomicInt<Int>::le)
            .def("__gt__", &AtomicInt<Int>::gt)
            .def("__ge__", &AtomicInt<Int>::ge)
            .def("__str__", &AtomicInt<Int>::str)
            .def("__getstate__", &AtomicInt<Int>::getstate)
            .def("__setstate__", &AtomicInt<Int>::setstate);
    }

private:
    std::atomic<Int> value;
};

PYBIND11_MODULE(atomix_base, m, py::mod_gil_not_used()) {
    py::class_<AtomicFlag>(m, "AtomicFlag")
        .def(py::init<>())
        .def(py::init<bool>())
        .def("clear", &AtomicFlag::clear)
        .def("test_and_set", &AtomicFlag::test_and_set)
        .def("test", &AtomicFlag::test)
        .def("wait", &AtomicFlag::wait)
        .def("notify_one", &AtomicFlag::notify_one)
        .def("notify_all", &AtomicFlag::notify_all)
        .def("__eq__", &AtomicFlag::operator==)
        .def("__neq__", &AtomicFlag::operator!=)
        .def("__getstate__", &AtomicFlag::getstate)
        .def("__setstate__", &AtomicFlag::setstate);

    AtomicInt<int64_t>.classDef(m, "AtomicInt64");
    AtomicInt<int32_t>.classDef(m, "AtomicInt32");
    AtomicInt<uint6_t4>.classDef(m, "AtomicUInt64");
    AtomicInt<uint3_t2>.classDef(m, "AtomicUInt32");
    // You could do this for all the int types if you wanted to...

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}
