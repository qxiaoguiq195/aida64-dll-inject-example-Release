#include "pch.h"
#include "keygen.h"

#pragma comment(lib, "version.lib")

namespace {
    constexpr char ALPHABET[] = "48M41-D38D6-UZDJT-11EAY-98YM5";

    bool base34_encode(uint32_t value, size_t width, std::string& out) {
        uint64_t limit = 1;
        for (size_t i = 0; i < width; ++i) {
            limit *= 34;
        }
        if (static_cast<uint64_t>(value) >= limit) {
            return false;
        }

        std::string chunk(width, 'D');
        for (size_t i = width; i-- > 0;) {
            chunk[i] = ALPHABET[value % 34];
            value /= 34;
        }
        out += chunk;
        return true;
    }

    uint32_t crc16_like(const std::string& text) {
        uint32_t value = 0;
        for (unsigned char c : text) {
            value ^= static_cast<uint32_t>(c) << 8;
            for (int i = 0; i < 8; ++i) {
                if (value & 0x8000u) {
                    value = ((value << 1) ^ 0x8201u) & 0xFFFFu;
                } else {
                    value = (value << 1) & 0xFFFFu;
                }
            }
        }
        return value;
    }

    char checksum_char(const std::string& first24) {
        uint32_t crc = crc16_like(first24) % 0x9987u;
        // base34_encode(crc, 3)[1] — middle char of 3-char encoding
        std::string tmp;
        base34_encode(crc, 3, tmp);
        return tmp[1];
    }

    uint32_t pack_base_date(int year, int month, int day) {
        return (static_cast<uint32_t>((year - 2003) & 0x1F) << 9)
             | (static_cast<uint32_t>(month & 0xF) << 5)
             | static_cast<uint32_t>(day & 0x1F);
    }

    uint32_t serial_limit_for_product(uint32_t product_id) {
        return (product_id == 1 || product_id == 4) ? 65533u : 776u;
    }

    uint32_t derive_serial(uint32_t product_id, uint32_t variant_code, uint32_t packed_date,
                           uint32_t expire_offset, uint32_t version_offset) {
        uint64_t mix = static_cast<uint64_t>(product_id)  * 0x45D
                     + static_cast<uint64_t>(variant_code) * 0x11
                     + static_cast<uint64_t>(packed_date)  * 3
                     + static_cast<uint64_t>(expire_offset)  * 5
                     + static_cast<uint64_t>(version_offset) * 7;
        return static_cast<uint32_t>(mix % serial_limit_for_product(product_id)) + 1;
    }

    uint32_t derive_seed(uint32_t product_id, uint32_t variant_code, uint32_t packed_date,
                         uint32_t expire_offset, uint32_t version_offset, uint32_t serial) {
        uint64_t mix = static_cast<uint64_t>(serial)
                     + static_cast<uint64_t>(product_id)  * 0x31
                     + static_cast<uint64_t>(variant_code) * 0x17
                     + static_cast<uint64_t>(packed_date)
                     + static_cast<uint64_t>(expire_offset)  * 7
                     + static_cast<uint64_t>(version_offset) * 11;
        return static_cast<uint32_t>(mix % (34u * 34u));
    }

    std::string group_key(const std::string& raw_key) {
        std::string grouped;
        grouped.reserve(raw_key.size() + raw_key.size() / 5);
        for (size_t i = 0; i < raw_key.size(); ++i) {
            if (i != 0 && i % 5 == 0) {
                grouped.push_back('-');
            }
            grouped.push_back(raw_key[i]);
        }
        return grouped;
    }

    bool contains_icase(const std::wstring& text, const wchar_t* needle) {
        return text.find(needle) != std::wstring::npos;
    }

    void to_lower_inplace(std::wstring& text) {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(towlower(ch));
        });
    }

    std::wstring query_version_string(const void* version_info, WORD language, WORD codepage, const wchar_t* name) {
        wchar_t sub_block[64]{};
        swprintf_s(sub_block, L"\\StringFileInfo\\%04x%04x\\%s", language, codepage, name);

        void* value = nullptr;
        UINT value_size = 0;
        if (!VerQueryValueW(version_info, sub_block, &value, &value_size) || value == nullptr || value_size == 0) {
            return {};
        }
        return std::wstring(static_cast<const wchar_t*>(value));
    }

    std::wstring read_version_info_product_name(HMODULE mod) {
        wchar_t path[MAX_PATH]{};
        const DWORD path_len = GetModuleFileNameW(mod, path, static_cast<DWORD>(std::size(path)));
        if (path_len == 0 || path_len >= std::size(path)) {
            return {};
        }

        DWORD handle = 0;
        const DWORD version_size = GetFileVersionInfoSizeW(path, &handle);
        if (version_size == 0) {
            return {};
        }

        std::vector<BYTE> version_info(version_size);
        if (!GetFileVersionInfoW(path, 0, version_size, version_info.data())) {
            return {};
        }

        struct Translation {
            WORD language;
            WORD codepage;
        };

        void* translation_ptr = nullptr;
        UINT translation_size = 0;
        if (VerQueryValueW(version_info.data(), L"\\VarFileInfo\\Translation", &translation_ptr, &translation_size)
            && translation_ptr != nullptr
            && translation_size >= sizeof(Translation)) {
            const auto* translations = static_cast<const Translation*>(translation_ptr);
            const size_t translation_count = translation_size / sizeof(Translation);
            for (size_t i = 0; i < translation_count; ++i) {
                std::wstring product_name = query_version_string(
                    version_info.data(), translations[i].language, translations[i].codepage, L"ProductName");
                if (!product_name.empty()) {
                    return product_name;
                }
            }
        }

        for (const Translation fallback : { Translation{ 0x0409, 0x04B0 }, Translation{ 0x0409, 1200 } }) {
            std::wstring product_name = query_version_string(version_info.data(), fallback.language, fallback.codepage, L"ProductName");
            if (!product_name.empty()) {
                return product_name;
            }
        }

        return {};
    }
}

ProductType detect_product_type()
{
    const HMODULE mod = GetModuleHandleW(nullptr);
    std::wstring product_name = read_version_info_product_name(mod);
    to_lower_inplace(product_name);

    if (contains_icase(product_name, L"business")) {
        return VER_BUSINESS;
    }
    if (contains_icase(product_name, L"extreme")) {
        return VER_EXTREME;
    }
    if (contains_icase(product_name, L"engineer")) {
        return VER_ENGINEER;
    }
    if (contains_icase(product_name, L"network")) {
        return VER_NETWORK;
    }
    // may add some more checks here. just fallback.
    return VER_BUSINESS;
}

std::string gen_key(ProductType pt, uint32_t subtype, std::time_t issue_date, std::time_t expire, std::time_t support_due)
{
    const uint32_t product_id = static_cast<uint32_t>(pt);
    if (product_id == 0 || product_id > 999) {
        return {};
    }

    // For product_id == 1 (Business), variant_code is always fixed to 100.
    const uint32_t variant_code = (product_id == 1) ? 100u : subtype;

    // Resolve base date (issue_date==0 means today).
    const std::time_t base_ts = issue_date ? issue_date : std::time(nullptr);
    struct tm tm_base{};
    localtime_s(&tm_base, &base_ts);
    const int b_year  = tm_base.tm_year + 1900;
    const int b_month = tm_base.tm_mon  + 1;
    const int b_day   = tm_base.tm_mday;

    // expire_offset and version_offset in days from base_date.
    constexpr uint32_t DEFAULT_OFFSET = 3652u;
    const uint32_t expire_offset = (expire > base_ts)
        ? std::min<uint32_t>(static_cast<uint32_t>((expire - base_ts) / 86400), DEFAULT_OFFSET)
        : DEFAULT_OFFSET;
    const uint32_t version_offset = (support_due > base_ts)
        ? std::min<uint32_t>(std::max<uint32_t>(static_cast<uint32_t>((support_due - base_ts) / 86400), 1u), DEFAULT_OFFSET)
        : DEFAULT_OFFSET;

    constexpr uint32_t FIELD_5_6 = 6u;
    constexpr uint32_t FIELD_7_8 = 1u;

    const uint32_t packed_date    = pack_base_date(b_year, b_month, b_day);
    const uint32_t serial         = derive_serial(product_id, variant_code, packed_date, expire_offset, version_offset);
    const uint32_t seed           = derive_seed(product_id, variant_code, packed_date, expire_offset, version_offset, serial);
    const uint32_t seed_low       = seed & 0xFFu;

    std::string first24;
    first24.reserve(24);
    if (!base34_encode(product_id   ^ seed_low ^ 0xBFu,   2, first24)
     || !base34_encode(variant_code ^ seed_low ^ 0xEDu,   2, first24)
     || !base34_encode(FIELD_5_6   ^ seed_low ^ 0x77u,   2, first24)
     || !base34_encode(FIELD_7_8   ^ seed_low ^ 0xDFu,   2, first24)
     || !base34_encode(serial      ^ seed     ^ 0x4755u,  4, first24)
     || !base34_encode(packed_date ^ seed     ^ 0x7CC1u,  4, first24)
     || !base34_encode(expire_offset  ^ seed_low ^ 0x3FDu,  3, first24)
     || !base34_encode(version_offset ^ seed_low ^ 0x935u,  3, first24)
     || !base34_encode(seed,                               2, first24)) {
        return {};
    }

    std::string raw_key = first24;
    raw_key += checksum_char(first24);
    return group_key(raw_key);
}
