#ifndef GEARS_MMAPSTREAM_HPP_
#define GEARS_MMAPSTREAM_HPP_

#include <gears/InputMemoryStream.hpp>
#include <gears/MMap.hpp>

namespace Gears
{
namespace MemoryStream
{
  /**
   * Input stream based on memory mapped file
   */
  template <typename Elem, typename Traits = std::char_traits<Elem> >
  class MMapStream:
    private Gears::MMapFile,
    public InputMemoryStream<Elem, Traits>
  {
  public:
    using Gears::MMapFile::Exception;

    /**
     * Constructor
     * @param filename file to open
     * @param size size to map (zero - from offset till the end)
     * @param offset starting offset in file
     */
    explicit
    MMapStream(const char* filename, size_t size = 0, off_t offset = 0)
      /*throw (Gears::Exception, Exception)*/;
  };
}
}

namespace Gears
{
  typedef MemoryStream::MMapStream<char> MMapFileStream;
  //typedef MemoryStream::MMapStream<wchar_t> WFileParser;
}

//
// Implementation
//

namespace Gears
{
namespace MemoryStream
{
  //
  // MMapParser class
  //

  template <typename Elem, typename Traits>
  MMapStream<Elem, Traits>::MMapStream(
    const char* filename,
    size_t size,
    off_t offset) /*throw (Gears::Exception, Exception)*/
    : Gears::MMapFile(filename, offset, size),
      InputMemoryStream<Elem, Traits>(
        static_cast<const Elem*>(this->memory()),
        this->length() / sizeof(Elem))
  {}
}
}

#endif
