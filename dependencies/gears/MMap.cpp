#include <unistd.h>

#include <limits>

#include <gears/Errno.hpp>
#include <gears/InputMemoryStream.hpp>
#include <gears/OutputMemoryStream.hpp>
#include <gears/MMap.hpp>

namespace Gears
{
  //
  // MMap class
  //

  void
  MMap::map_(
    int fd,
    void* preferrable_address,
    size_t size,
    off_t offset,
    int mmap_prot,
    int mmap_flags) /*throw (Gears::Exception, Exception)*/
  {
    static const char* FUN = "MMap::map_()";
    static const char* FNE = "MMap::map_(): ";

    off_t file_size = size;
    if (fd >= 0)
    {
      file_size = lseek(fd, 0, SEEK_END);
      if (file_size == static_cast<off_t>(-1))
      {
        Gears::throw_errno_exception<Exception>(FNE,
          "Failed to determine size of file");
      }

      if (offset + static_cast<off_t>(size) > file_size)
      {
        ErrorStream ostr;
        ostr << FUN << ": Map window of offset " << offset << " and size " <<
          size << " exceeds file's size of " << file_size;
        throw Exception(ostr.str());
      }

      file_size -= offset;
    }

    length_ = size;
    if (!length_)
    {
      if (std::numeric_limits<ssize_t>::max() < file_size)
      {
        ErrorStream ostr;
        ostr << FUN << ": requested map length " << file_size <<
          " is too large";
        throw Exception(ostr.str());
      }
      length_ = static_cast<ssize_t>(file_size);
    }

    memory_ = mmap(preferrable_address, length_, mmap_prot, mmap_flags, fd,
      offset);
    if (memory_ == MAP_FAILED)
    {
      memory_ = 0;
      Gears::throw_errno_exception<Exception>(FNE, "mmap failed");
    }
  }

  MMap::MMap() noexcept
    : memory_(0), length_(0)
  {}

  MMap::MMap(int fd, size_t size, off_t offset, int mmap_prot,
    int mmap_flags) /*throw (Gears::Exception, Exception)*/
  {
    map_(fd, 0, size, offset, mmap_prot, mmap_flags);
  }

  MMap::MMap(void* preferrable_address, std::size_t size)
    /*throw (Gears::Exception, Exception)*/
  {
    map_(-1, preferrable_address, size, 0, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_ANONYMOUS);
  }

  MMap::~MMap() noexcept
  {
    munmap(memory_, length_);
  }

  void*
  MMap::memory() const noexcept
  {
    return memory_;
  }

  size_t
  MMap::length() const noexcept
  {
    return length_;
  }


  //
  // MMap class
  //

  MMapFile::MMapFile(
    const char* filename,
    size_t size,
    off_t offset,
    int flags, int mmap_prot, int mmap_flags)
    /*throw (Gears::Exception, Exception)*/
  {
    static const char* FUN = "MMapFile::MMapFile()";
    static const char* FNE = "MMapFile::MMapFile(): ";

    if (offset < 0)
    {
      ErrorStream ostr;
      ostr << FUN << ": offset is negative";
      throw Exception(ostr.str());
    }

    fd_ = open(filename, flags, 0666);
    if (fd_ < 0)
    {
      Gears::throw_errno_exception<Exception>(FNE, "Failed to open file '",
        filename, "'");
    }

    try
    {
      map_(fd_, 0, size, offset, mmap_prot, mmap_flags);
    }
    catch (...)
    {
      close(fd_);
      throw;
    }
  }

  MMapFile::MMapFile(int fd, size_t size, off_t offset,
    int mmap_prot, int mmap_flags)
    /*throw (Gears::Exception, Exception)*/
    : fd_(fd)
  {
    static const char* FUN = "MMapFile::MMapFile()";

    if (fd_ < 0)
    {
      ErrorStream ostr;
      ostr << FUN << ": invalid file descriptor";
      throw Exception(ostr.str());
    }

    try
    {
      if (offset < 0)
      {
        ErrorStream ostr;
        ostr << FUN << ": offset is negative";
        throw Exception(ostr.str());
      }

      map_(fd_, 0, size, offset, mmap_prot, mmap_flags);
    }
    catch (...)
    {
      close(fd_);
      throw;
    }
  }

  MMapFile::~MMapFile() noexcept
  {
    close(fd_);
  }

  int
  MMapFile::file_descriptor() const noexcept
  {
    return fd_;
  }
}
