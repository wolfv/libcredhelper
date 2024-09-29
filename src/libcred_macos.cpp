#include <Security/Security.h>
#include "libcred.hpp"


namespace libcred
{

    /**
     * Converts a CFString to a std::string
     *
     * This either uses CFStringGetCStringPtr or (if that fails)
     * CFStringGetCString, trying to be as efficient as possible.
     */
    const std::string CFStringToStdString(CFStringRef cfstring)
    {
        const char* cstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

        if (cstr != NULL)
        {
            return std::string(cstr);
        }

        CFIndex length = CFStringGetLength(cfstring);
        // Worst case: 2 bytes per character + NUL
        CFIndex cstrPtrLen = length * 2 + 1;
        char* cstrPtr = static_cast<char*>(malloc(cstrPtrLen));

        Boolean result = CFStringGetCString(cfstring, cstrPtr, cstrPtrLen, kCFStringEncodingUTF8);

        std::string stdstring;
        if (result)
        {
            stdstring = std::string(cstrPtr);
        }

        free(cstrPtr);

        return stdstring;
    }

    const std::string errorStatusToString(OSStatus status)
    {
        std::string errorStr;
        CFStringRef errorMessageString = SecCopyErrorMessageString(status, NULL);

        const char* errorCStringPtr
            = CFStringGetCStringPtr(errorMessageString, kCFStringEncodingUTF8);
        if (errorCStringPtr)
        {
            errorStr = std::string(errorCStringPtr);
        }
        else
        {
            errorStr = std::string("An unknown error occurred.");
        }

        CFRelease(errorMessageString);
        return errorStr;
    }

    LIBCRED_RESULT AddPassword(const std::string& service,
                               const std::string& account,
                               const std::string& password,
                               std::string* error)
    {
        CFStringRef serviceRef
            = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);
        CFStringRef accountRef
            = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);
        CFDataRef passwordDataRef = CFDataCreate(
            NULL, reinterpret_cast<const UInt8*>(password.c_str()), password.length());

        CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(
            NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(attributes, kSecClass, kSecClassInternetPassword);
        CFDictionaryAddValue(attributes, kSecAttrServer, serviceRef);
        CFDictionaryAddValue(attributes, kSecAttrAccount, accountRef);
        CFDictionaryAddValue(attributes, kSecValueData, passwordDataRef);

        // Add the item to the keychain
        OSStatus status = SecItemAdd(attributes, NULL);

        if (status != errSecSuccess)
        {
            *error = errorStatusToString(status);
            return FAIL_ERROR;
        }

        return SUCCESS;
    }

    LIBCRED_RESULT set_password(const std::string& service,
                                const std::string& account,
                                const std::string& password,
                                std::string* error)
    {
        CFStringRef cfAccount
            = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);
        CFStringRef cfService
            = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);
        CFDataRef cfNewPassword
            = CFDataCreate(NULL, (const UInt8*) password.c_str(), password.length());

        const void* queryKeys[] = { kSecClass, kSecAttrAccount, kSecAttrServer };
        const void* queryValues[] = { kSecClassInternetPassword, cfAccount, cfService };
        CFDictionaryRef query = CFDictionaryCreate(NULL,
                                                   queryKeys,
                                                   queryValues,
                                                   3,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks);

        // Create an update dictionary with the new password
        const void* updateKeys[] = { kSecValueData };
        const void* updateValues[] = { cfNewPassword };
        CFDictionaryRef update = CFDictionaryCreate(NULL,
                                                    updateKeys,
                                                    updateValues,
                                                    1,
                                                    &kCFTypeDictionaryKeyCallBacks,
                                                    &kCFTypeDictionaryValueCallBacks);

        // Perform the update
        OSStatus status = SecItemUpdate(query, update);

        if (status == errSecItemNotFound)
        {
            return AddPassword(service, account, password, error);
        }
        else if (status != errSecSuccess)
        {
            *error = errorStatusToString(status);
            return FAIL_ERROR;
        }

        // Clean up
        CFRelease(cfAccount);
        CFRelease(cfService);
        CFRelease(cfNewPassword);
        CFRelease(query);
        CFRelease(update);

        return SUCCESS;
    }

    LIBCRED_RESULT get_password(const std::string& service,
                                const std::string& account,
                                std::string* password,
                                std::string* error)
    {
        CFStringRef cfAccount
            = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);
        CFStringRef cfService
            = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);

        const void* keys[]
            = { kSecClass, kSecAttrAccount, kSecAttrServer, kSecReturnData, kSecMatchLimit };
        const void* values[] = {
            kSecClassInternetPassword, cfAccount, cfService, kCFBooleanTrue, kSecMatchLimitOne
        };

        CFDictionaryRef query = CFDictionaryCreate(NULL,
                                                   keys,
                                                   values,
                                                   5,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks);

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching(query, &result);

        CFRelease(cfAccount);
        CFRelease(cfService);
        CFRelease(query);

        if (status == errSecItemNotFound)
        {
            return FAIL_NONFATAL;
        }
        else if (status != errSecSuccess)
        {
            *error = errorStatusToString(status);
            return FAIL_ERROR;
        }

        CFDataRef passwordData = (CFDataRef) result;
        *password = std::string((const char*) CFDataGetBytePtr(passwordData),
                                CFDataGetLength(passwordData));
        CFRelease(passwordData);
        return SUCCESS;
    }

    LIBCRED_RESULT delete_password(const std::string& service,
                                   const std::string& account,
                                   std::string* error)
    {
        // Create a query dictionary to find the existing item
        CFStringRef cfAccount
            = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);
        CFStringRef cfService
            = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);

        const void* keys[] = { kSecClass, kSecAttrAccount, kSecAttrServer };
        const void* values[] = { kSecClassInternetPassword, cfAccount, cfService };

        CFDictionaryRef query = CFDictionaryCreate(NULL,
                                                   keys,
                                                   values,
                                                   3,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks);

        // Perform the deletion
        OSStatus status = SecItemDelete(query);

        // Clean up
        CFRelease(cfAccount);
        CFRelease(cfService);
        CFRelease(query);

        if (status == errSecItemNotFound)
        {
            // Item could not be found, so already deleted.
            return FAIL_NONFATAL;
        }
        else if (status != errSecSuccess)
        {
            *error = errorStatusToString(status);
            return FAIL_ERROR;
        }

        return SUCCESS;
    }

    LIBCRED_RESULT find_password(const std::string& service,
                                 std::string* password,
                                 std::string* error)
    {
        // Create a query dictionary
        CFStringRef cfService
            = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);

        const void* keys[] = { kSecClass, kSecAttrServer, kSecReturnData, kSecMatchLimit };
        const void* values[]
            = { kSecClassInternetPassword, cfService, kCFBooleanTrue, kSecMatchLimitOne };

        CFDictionaryRef query = CFDictionaryCreate(NULL,
                                                   keys,
                                                   values,
                                                   4,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks);

        // Perform the query
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching(query, &result);

        // Clean up
        CFRelease(cfService);
        CFRelease(query);

        if (status == errSecItemNotFound)
        {
            return FAIL_NONFATAL;
        }
        else if (status != errSecSuccess)
        {
            *error = errorStatusToString(status);
            return FAIL_ERROR;
        }

        CFDataRef passwordData = (CFDataRef) result;
        *password = std::string((const char*) CFDataGetBytePtr(passwordData),
                                CFDataGetLength(passwordData));
        CFRelease(passwordData);

        return SUCCESS;
    }

    Credentials getCredentialsForItem(CFDictionaryRef item)
    {
        CFStringRef service = (CFStringRef) CFDictionaryGetValue(item, kSecAttrService);
        CFStringRef account = (CFStringRef) CFDictionaryGetValue(item, kSecAttrAccount);

        CFMutableDictionaryRef query = CFDictionaryCreateMutable(
            NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        CFDictionaryAddValue(query, kSecAttrService, service);
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne);
        CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
        CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);
        CFDictionaryAddValue(query, kSecAttrAccount, account);

        Credentials cred;
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

        CFRelease(query);

        if (status == errSecSuccess)
        {
            CFDataRef passwordData
                = (CFDataRef) CFDictionaryGetValue((CFDictionaryRef) result, CFSTR("v_Data"));
            CFStringRef password = CFStringCreateFromExternalRepresentation(
                NULL, passwordData, kCFStringEncodingUTF8);

            cred = Credentials(CFStringToStdString(account), CFStringToStdString(password));

            CFRelease(password);
        }

        if (result != NULL)
        {
            CFRelease(result);
        }

        return cred;
    }

    LIBCRED_RESULT find_credentials(const std::string& service,
                                    std::vector<Credentials>* credentials,
                                    std::string* error)
    {
        CFStringRef serviceStr
            = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);

        CFMutableDictionaryRef query = CFDictionaryCreateMutable(
            NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionaryAddValue(query, kSecAttrService, serviceStr);
        CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);
        CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
        CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

        CFRelease(serviceStr);
        CFRelease(query);

        if (status == errSecSuccess)
        {
            CFArrayRef resultArray = (CFArrayRef) result;
            int resultCount = CFArrayGetCount(resultArray);

            for (int idx = 0; idx < resultCount; idx++)
            {
                CFDictionaryRef item = (CFDictionaryRef) CFArrayGetValueAtIndex(resultArray, idx);

                Credentials cred = getCredentialsForItem(item);
                credentials->push_back(cred);
            }
        }
        else if (status == errSecItemNotFound)
        {
            return FAIL_NONFATAL;
        }
        else
        {
            *error = errorStatusToString(status);
            return FAIL_ERROR;
        }

        if (result != NULL)
        {
            CFRelease(result);
        }

        return SUCCESS;
    }

}  // namespace keytar