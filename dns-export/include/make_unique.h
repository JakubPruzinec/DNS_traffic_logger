/* source https://herbsutter.com/gotw/_102/ */
#ifndef _CUSTOM_MAKE_UNIQUE_H_
#define _CUSTOM_MAKE_UNIQUE_H_

#include <memory>

namespace std
{

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

} // std

#endif