#include "include/pluginInterface/interfaceHashScheme.h"

  // C++ library

#include <memory>
#include <random>

  // Miscellaneous libraries

#include <crypt.h>
#include <GCL>

  // msmERP header files


namespace pluginHashScheme
{
  std::string const SCRYPT_SALTLENGTH       ("scrypt/SaltLength");
  std::string const SCRYPT_CPUTIME          ("scrypt/CPUTime");

  static GCL::CReaderSections const *configurationReader = nullptr;

  /// @brief Initialise the plugin. Must be called before any password functions are called.
  /// @param[in] cr: Pointer to the configuration file reader.
  /// @throws None
  /// /// @note If this is not called, then defaults will be used.
  /// @version 2022-11-10/GGB - Function created.

  void initialisePlugin(GCL::CReaderSections const *cr)
  {
    configurationReader = cr;
  }

  void __attribute__ ((destructor)) destroyPlugin()
  {
  }


  /// @brief Returns a string containing the hashing method.
  /// @returns Reference to the hashing method
  /// @throws
  /// @version 2022-11-10/GGB - Function created.

  std::string const &hashMethod()
  {
    static std::string const method = "scrypt";

    return method;
  }

  /// @brief Creates a salt and hash for a new password.
  /// @param[in] salt: The salt created.
  /// @param[in] hash: The hashed password.
  /// @param[in] password: The new password to hash.
  /// @version 2022-07-16/GGB - Function created.

  void createHash(std::string &salt, std::string &hash, std::string const &password)
  {
    std::string chrs = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    salt.clear();
    hash.clear();

    std::optional<std::uint16_t> saltLength = configurationReader->tagValueUInt16(SCRYPT_SALTLENGTH);
    std::optional<std::uint16_t> rounds = configurationReader->tagValueUInt16(SCRYPT_CPUTIME);

    if (!rounds)
    {
      rounds = 9;
    }

    if (!saltLength)
    {
      saltLength = 32;
    }

    std::random_device rd;
    std::default_random_engine e1(rd());
    std::uniform_int_distribution<int> uniform_dist(0, chrs.length()-1);

      // Generate the salt.

    for (auto i = 0; i < saltLength; i++)
    {
      salt.push_back(chrs[uniform_dist(e1)]);
    }
    salt.push_back(0);

      // Generate the hash

    crypt_data data;
    std::string prefix = "$7$";
    char setting[CRYPT_GENSALT_OUTPUT_SIZE];

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);

    crypt_gensalt_rn(prefix.c_str(), *rounds, salt.c_str(), *saltLength, setting, CRYPT_GENSALT_OUTPUT_SIZE);
    crypt_r(password.c_str(), setting, &data);

    std::string_view sv(data.output);

    hash = sv;

      // Zero out the memory.

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);
  }

  /// @brief Authenticates the password against the hash.
  /// @param[in] salt: The salt value.
  /// @param[in] hash: The hashed password value.
  /// @param[in] password: The password to verify.
  /// @returns true if the password matches the hash.
  /// @throws
  /// @version 2022-11-10/GGB - Function created.

  bool authenticate(std::string const &salt, std::string const &hash, std::string const &password)
  {
    bool returnValue = false;
    crypt_data data;
    char setting[CRYPT_GENSALT_OUTPUT_SIZE];

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);

    crypt_r(password.c_str(), hash.c_str(), &data);

    std::string_view sv(data.output);

    returnValue = (sv == hash);

    std::cout << "Return Value: " << returnValue << std::endl;

      // Zero out the memory. It is on the stack so should get reused fairly quickly.

    std::fill(reinterpret_cast<volatile char *>(&data), reinterpret_cast<volatile char *>(&data) + sizeof(data), 0);

    return returnValue;
  }


} // namespace
