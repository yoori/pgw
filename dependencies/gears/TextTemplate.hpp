#ifndef GEARS_TEXTTEMPLATE_HPP_
#define GEARS_TEXTTEMPLATE_HPP_

#include <istream>
#include <memory>
#include <deque>
#include <set>

#include <gears/OutputMemoryStream.hpp>
#include <gears/HashTable.hpp>
#include <gears/HashTableAdapters.hpp>

namespace Gears
{
namespace TextTemplate
{
  DECLARE_EXCEPTION(TextTemplException, Gears::DescriptiveException);
  DECLARE_EXCEPTION(InvalidTemplate, TextTemplException);
  DECLARE_EXCEPTION(UnknownName, TextTemplException);

  /**
   * Callback context. Determines values for keys.
   */
  class ArgsCallback
  {
  public:
    /**
     * Destructor
     */
    virtual
    ~ArgsCallback() noexcept;

    /**
     * Returns value for a key.
     * @param key Text of a key.
     * @param result Value corresponding with the key.
     * @param value if false return key name if has value to supply.
     * @return whether key was processed or not
     */
    virtual
    bool
    get_argument(
      const SubString& key, std::string& result,
      bool value = true) const /*throw (Gears::Exception)*/ = 0;
  };


  typedef std::set<std::string> Keys;

  /**
   * Text template. Replace keys with values in a pattern.
   * Works on SubString supplied.
   */
  class Basic : private Gears::Uncopyable
  {
  public:
    static const SubString DEFAULT_LEXEME;

    /**
     * Constructor.
     */
    Basic() noexcept;

    /**
     * Constructor. Calls init.
     * @param str template to parse
     * @param start_lexeme Start lexeme.
     * @param end_lexeme End lexeme.
     * @exception InvalidTemplate Invalid template.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    explicit
    Basic(const SubString& str,
          const SubString& start_lexeme = DEFAULT_LEXEME,
          const SubString& end_lexeme = DEFAULT_LEXEME)
      /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/;

    /**
     * Destructor.
     */
    virtual
    ~Basic() noexcept;

    /**
     * Initializes a pattern.
     * @param str template to parse
     * @param start_lexeme Start lexeme.
     * @param end_lexeme End lexeme.
     * @exception InvalidTemplate Invalid template.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    void
    init(const SubString& str,
         const SubString& start_lexeme = DEFAULT_LEXEME,
         const SubString& end_lexeme = DEFAULT_LEXEME)
      /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/;

    /**
     * Instantiation of a pattern.
     * @param args supplier of values for found keys
     * @return instantiated template
     * @exception UnknownName Invalid or unknown key.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    std::string
    instantiate(const ArgsCallback& args) const
      /*throw (UnknownName, TextTemplException, Gears::Exception)*/;

    /**
     * Building a set of keys args contains values for.
     * @param args supplier of values for found keys
     * @param keys resulted keys set
     * @exception UnknownName Invalid or unknown key.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    void
    keys(const ArgsCallback& args, Keys& keys) const
      /*throw (UnknownName, TextTemplException, Gears::Exception)*/;

    /**
     * Tests whether the template is contains items or not
     * @return true if contains
     */
    bool
    empty() const /*throw (Gears::Exception)*/;

  private:
    /**
     * Base item interface.
     */
    class Item
    {
    protected:
      /**
       * Destructor
       */
      virtual
      ~Item() noexcept;

    public:
      /**
       * Add value of item to destination string.
       * @param callback Informational callback
       * @param dst Append value of item to it
       */
      virtual
      void
      append_value(const ArgsCallback& callback, std::string& dst) const
        /*throw (Gears::Exception)*/ = 0;

      /**
       * Checks if callback contains the specific value if it's required
       * @param callback Informational callback
       * @return required key name or empty if not required
       */
      virtual
      std::string
      key(const ArgsCallback& callback) const
        /*throw (Gears::Exception)*/ = 0;
    };

    typedef std::shared_ptr<Item> Item_var;

    /**
     * String item.
     */
    class StringItem : public Item
    {
    public:
      StringItem(const SubString& val) /*throw (Gears::Exception)*/;

      /**
       * Destructor
       */
      virtual
      ~StringItem() noexcept;

      /**
       * Adds stored value to destination string.
       * @param callback Informational callback
       * @param dst Append value of item to it
       */
      virtual
      void
      append_value(const ArgsCallback& callback, std::string& dst) const
        /*throw (Gears::Exception)*/;

      /**
       * Does nothing
       * @param callback Informational callback
       * @return empty SubString
       */
      virtual
      std::string
      key(const ArgsCallback& callback) const
        /*throw (Gears::Exception)*/;

    private:
      SubString value_;
    };

    /**
     * Variable item.
     */
    class VarItem : public Item
    {
    public:
      VarItem(const SubString& key) /*throw (Gears::Exception)*/;

      /**
       * Destructor
       */
      virtual
      ~VarItem() noexcept;

      /**
       * Founds value for the stored key and adds it to destination
       * string.
       * @param callback Informational callback
       * @param dst Append value to it
       */
      virtual
      void
      append_value(const ArgsCallback& callback, std::string& dst) const
        /*throw (Gears::Exception)*/;

      /**
       * Checks if callback contains the value for the key
       * @param callback Informational callback
       * @return required key name
       */
      virtual
      std::string
      key(const ArgsCallback& callback) const
        /*throw (Gears::Exception)*/;

    private:
      SubString key_;
    };

  private:
    typedef std::deque<Item_var> Items;

    Items items_;
  };

  /**
   * Text template. Replace keys with values in a pattern.
   * Stores SubString supplied in std::string and works on it.
   */
  class String : public Basic
  {
  public:
    String() noexcept;

    /**
     * Constructor. Calls init.
     * @param str template to copy and parse
     * @param start_lexeme Start lexeme.
     * @param end_lexeme End lexeme.
     * @exception InvalidTemplate Invalid template.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    explicit
    String(
      const SubString& str,
      const SubString& start_lexeme = DEFAULT_LEXEME,
      const SubString& end_lexeme = DEFAULT_LEXEME)
      /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/;

    virtual
    ~String() noexcept;

    /**
     * Initializes a pattern.
     * @param str template to copy and parse
     * @param start_lexeme Start lexeme.
     * @param end_lexeme End lexeme.
     * @exception InvalidTemplate Invalid template.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    void
    init(
      const SubString& str,
      const SubString& start_lexeme = DEFAULT_LEXEME,
      const SubString& end_lexeme = DEFAULT_LEXEME)
      /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/;

  protected:
    std::string text_template_;
  };

  /**
   * Text template. Replace keys with values in a pattern.
   * Stores content of std::istream supplied in std::string and 
   * works on it.
   */
  class IStream : public String
  {
  public:
    /**
     * Constructor
     */
    IStream() noexcept;

    /**
     * Initializes a pattern.
     * @param istr stream to read and parse
     * @param start_lexeme Start lexeme.
     * @param end_lexeme End lexeme.
     * @exception InvalidTemplate Invalid template.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    explicit
    IStream(
      std::istream& istr,
      const SubString& start_lexeme = DEFAULT_LEXEME,
      const SubString& end_lexeme = DEFAULT_LEXEME)
      /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/;

    /**
     * Destructor
     */
    virtual
    ~IStream() noexcept;

    /**
     * Initializes a pattern.
     * @param istr stream to read and parse
     * @param start_lexeme Start lexeme.
     * @param end_lexeme End lexeme.
     * @exception InvalidTemplate Invalid template.
     * @exception TextTemplException Other errors.
     * @exception Gears::Exception std::exception.
     */
    void
    init(
      std::istream& istr,
      const SubString& start_lexeme = DEFAULT_LEXEME,
      const SubString& end_lexeme = DEFAULT_LEXEME)
      /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/;
  };


  /**
   * General adapter for ArgsContainer
   */
  struct ArgsContainerAdapter
  {
    static
    const SubString&
    real_key(const SubString& key) noexcept;

    template <typename Iterator>
    static
    std::string
    value(const Iterator& itor)
      /*throw (Gears::Exception)*/;
  };

  /**
   * Specific adapter for ArgsContainer
   */
  struct ArgsContainerStringAdapter : public ArgsContainerAdapter
  {
    static
    std::string
    real_key(const SubString& key) /*throw (Gears::Exception)*/;
  };

  /**
   * Implementation of ArgsCallback using Container to find
   * values for corresponding keys
   */
  template <typename Container, typename Adapter = ArgsContainerAdapter>
  class ArgsContainer : public ArgsCallback
  {
  public:
    /**
     * Constructor to save pointer to container that able find keys.
     * @param cont pointer to container
     */
    explicit
    ArgsContainer(const Container* cont) noexcept;

    /**
     * Returns value for a key.
     * @param key Text of a key.
     * @param result Value corresponding with the key.
     * @param value if false return key name if has value to supply.
     * @return whether key was processed or not
     */
    virtual
    bool
    get_argument(const SubString& key, std::string& result,
                 bool value = true) const /*throw (Gears::Exception)*/;

  private:
    const Container* cont_;
  };

  /**
   * Implementation of ArgsCallback using default values found in keys
   * names or using additional ArgsCallback for lacking ones.
   */
  class DefaultValue : public ArgsCallback
  {
  public:
    /**
     * Constructor
     * @param callback callback for keys lacking default values
     */
    explicit
    DefaultValue(const ArgsCallback* callback) noexcept;

    /**
     * Returns value for a key.
     * @param key Text of a key.
     * @param result Value corresponding with the key.
     * @param value if false return key name if has value to supply.
     * @return whether key was processed or not
     */
    virtual
    bool
    get_argument(const SubString& key, std::string& result,
                 bool value = true) const /*throw (Gears::Exception)*/;

    const ArgsCallback* callback_;
  };

  /**
   * ArgsEncoder implements simple encoding enabled text template
   * arguments provider.
   */
  class ArgsEncoder : public ArgsCallback
  {
  public:
    typedef void (*ValueEncoder)(
      std::string&& value,
      std::string& encoded);

    /**
     * EncoderItem class is required for
     * 1. Registration of default encoding types
     * 2. Transfer of (probable default) encoding type into
     *    Args
     */
    class EncoderItem
    {
    public:
      /**
       * Constructor
       * @param encode Function providing encoding
       */
      explicit
      EncoderItem(ValueEncoder encode) noexcept;

      /**
       * Constructor
       * Registers encoder in the common EncoderHolder
       * @param key Unique encoder key, static constant only
       * @param encoder Function providing encoding
       */
      EncoderItem(const char* key, ValueEncoder encoder)
        /*throw (Gears::Exception)*/;

      /**
       * Getter for saved encoder
       * @return Saved encoder
       */
      ValueEncoder
      get_encoder_() const noexcept;

    private:
      ValueEncoder encoder_;
    };

  public:
    static const EncoderItem EI_UTF8;
    static const EncoderItem EI_MIME_URL;
    static const EncoderItem EI_XML;
    static const EncoderItem EI_JS;
    static const EncoderItem EI_JS_UNICODE;

    /**
     * A constructor.
     * @param args_container Container of arguments
     * @param encode Inform get_argument to distinguish encoding prefix in
     * key string
     * @param error_if_no_key if true raise ::UnknownName
     * exception when key not found.
     * @param default_encoding Text using encoding
     */
    explicit
    ArgsEncoder(
      ArgsCallback* args_container,
      bool encode = true,
      bool error_if_no_key = true,
      const EncoderItem& default_encoding = EI_UTF8)
      /*throw (UnknownName, Gears::Exception)*/;

    /**
     * Set callback
     * @param args_container Pointer to the new callback
     */
    void
    set_callback(ArgsCallback* args_container)
      noexcept;

    /**
     * Returns value for a key.
     * @param key Text of a key.
     * @param result Value corresponding with the key.
     * @param value if false return key name if has value to supply.
     * @return whether key was processed or not
     * @exception Gears::Exception std::exception.
     */
    virtual
    bool
    get_argument(
      const SubString& key,
      std::string& result,
      bool value = true) const /*throw (Gears::Exception)*/;

  protected:
    ArgsCallback* args_container_;
    const bool ENCODE_;
    const bool ERROR_IF_NO_KEY_;
    const ValueEncoder DEFAULT_ENCODER_;
  };

  /**
   * Args class
   */
  class Args :
    public ArgsEncoder,
    public Gears::HashTable<
      Gears::StringHashAdapter, std::string>
  {
  public:
    /**
     * A constructor.
     * @param encode Inform get_argument to distinguish encoding prefix in
     * key string
     * @param table_size defines hash table size
     * @param error_if_no_key if true raise ::UnknownName
     * exception when key not found.
     * @param default_encoding Text using encoding
     * @param has_defaults True switch on callback for default values.
     */
    explicit
    Args(
      bool encode = true,
      unsigned long table_size = 200,
      bool error_if_no_key = true,
      const EncoderItem& default_encoding = EI_UTF8,
      bool has_defaults = true)
      /*throw (UnknownName, Gears::Exception)*/;

    ~Args() noexcept;

  protected:
    typedef Gears::HashTable<
      Gears::StringHashAdapter, std::string> ValueContainer;

    ArgsContainer<ValueContainer> args_container_;
    DefaultValue default_value_callback_;
  };

  //
  // UpdateStrategy class
  //

  /**
   * UpdateStrategy provides an interface for Default class
   * to be used in conjunction with FileCache to provide
   * "cacheable text file template" functionality.
   */
  class UpdateStrategy
  {
  public:
    /**
     * Declare IStream class to be a FileCache buffer
     */
    typedef const IStream Buffer;

    /**
     * Constructs UpdateStrategy object that will hold
     * text template file name and use it to update Default instance.
     * @param fname file name.
     */
    explicit
    UpdateStrategy(const char* fname) /*throw (Gears::Exception)*/;

    /**
     * Destructs UpdateStrategy object
     */
    virtual
    ~UpdateStrategy() noexcept;

    /**
     * Provides reference to Default object as a in-memory buffer of a
     * template file.
     * @return Returns reference to the stored Default object.
     */
    Buffer&
    get() noexcept;

    /**
     * Updates stored Default object from a template file.
     * Called by FileCache when file changes.
     */
    void
    update() /*throw (TextTemplException, Gears::Exception)*/;

    /**
     * Provides text template lexeme which starts template variable entry.
     * Should be implemented in derived class.
     * @return Returns starting lexeme.
     */
    virtual
    SubString
    start_lexeme() const /*throw (Gears::Exception)*/ = 0;

    /**
     * Provides text template lexeme which ends template variable entry.
     * Should be implemented in derived class.
     * @return Returns ending lexeme.
     */
    virtual
    SubString
    end_lexeme() const /*throw (Gears::Exception)*/ = 0;

  private:
    IStream text_template_;
    std::string fname_;
  };
}
}

//
// INLINES
//

namespace Gears
{
namespace TextTemplate
{
  //
  // ArgsCallback class
  //

  inline
  ArgsCallback::~ArgsCallback() noexcept
  {}

  //
  // Basic class
  //

  inline
  Basic::Basic() noexcept
  {}

  inline
  Basic::~Basic() noexcept
  {}

  inline
  bool
  Basic::empty() const /*throw (Gears::Exception)*/
  {
    return items_.empty();
  }

  //
  // String class
  //

  inline
  String::String() noexcept
  {}

  inline
  String::~String() noexcept
  {}


  //
  // IStream class
  //

  inline
  IStream::IStream() noexcept
  {}

  inline
  IStream::~IStream() noexcept
  {}

  //
  // ArgsContainerAdapter class
  //

  inline
  const SubString&
  ArgsContainerAdapter::real_key(const SubString& key) noexcept
  {
    return key;
  }

  template <typename Iterator>
  std::string
  ArgsContainerAdapter::value(const Iterator& itor)
    /*throw (Gears::Exception)*/
  {
    return itor->second;
  }

  //
  // ArgsContainerAdapter class
  //

  inline
  std::string
  ArgsContainerStringAdapter::real_key(const SubString& key)
    /*throw (Gears::Exception)*/
  {
    return key.str();
  }

  //
  // ArgsContainer class
  //

  template <typename Container, typename Adapter>
  ArgsContainer<Container, Adapter>::ArgsContainer(const Container* cont)
    noexcept
    : cont_(cont)
  {}

  template <typename Container, typename Adapter>
  bool
  ArgsContainer<Container, Adapter>::get_argument(
    const SubString& key, std::string& result, bool value) const
    /*throw (Gears::Exception)*/
  {
    if (!value)
    {
      key.assign_to(result);
      return true;
    }

    typename Container::const_iterator it =
      cont_->find(Adapter::real_key(key));
    if (it == cont_->end())
    {
      return false;
    }
    result = Adapter::value(it);
    return true;
  }

  //
  // Args::EncoderItem class
  //

  inline
  ArgsEncoder::EncoderItem::EncoderItem(ValueEncoder encoder) noexcept
    : encoder_(encoder)
  {}

  inline
  ArgsEncoder::ValueEncoder
  ArgsEncoder::EncoderItem::get_encoder_() const noexcept
  {
    return encoder_;
  }


  //
  // Args class
  //

  inline
  Args::~Args() noexcept
  {}

  //
  // UpdateStrategy class
  //

  inline
  UpdateStrategy::UpdateStrategy(const char* fname)
    /*throw (Gears::Exception)*/
    : fname_(fname ? fname : "")
  {}

  inline
  UpdateStrategy::~UpdateStrategy() noexcept
  {}

  inline
  UpdateStrategy::Buffer&
  UpdateStrategy::get() noexcept
  {
    return text_template_;
  }
}
}

#endif
