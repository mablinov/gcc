// { dg-do compile { target c++11 } }
#include <memory>

// 2762. unique_ptr operator*() should be noexcept
static_assert( noexcept(*std::declval<std::unique_ptr<long>>()), "LWG 2762" );

template<bool B>
struct deleter
{
  struct pointer
  {
    int& operator*() && noexcept(B);  // this is used by unique_ptr
    int& operator*() const& = delete; // this should not be

    int& operator[](std::size_t) && noexcept(B); // this is used by unique_ptr
    int& operator[](std::size_t) const& = delete; // should not be used
    int& operator[](int) && = delete; // should not be used
    int& operator[](double) && = delete; // should not be used

    int* operator->() noexcept(false); // noexcept here doesn't affect anything

    // Needed for NullablePointer requirements
    pointer(int* = nullptr);
    bool operator==(const pointer&) const noexcept;
    bool operator!=(const pointer&) const noexcept;
  };

  void operator()(pointer) const noexcept { }
};

template<typename T, bool Nothrow>
  using UPtr = std::unique_ptr<T, deleter<Nothrow>>;

// noexcept-specifier depends on the pointer type
static_assert( noexcept(*std::declval<UPtr<int, true>&>()), "" );
static_assert( ! noexcept(*std::declval<UPtr<int, false>&>()), "" );

// This has always been required, even in C++11.
static_assert( noexcept(std::declval<UPtr<int, false>&>().operator->()), "" );

// This is not required by the standard
static_assert( noexcept(std::declval<UPtr<int[], true>&>()[0]), "" );
static_assert( ! noexcept(std::declval<UPtr<int[], false>&>()[0]), "" );
