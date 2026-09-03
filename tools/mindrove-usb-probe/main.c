// SPDX-License-Identifier: GPL-2.0-only

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MINDROVE_VENDOR_ID 0x0bda
#define MINDROVE_PRODUCT_ID 0xc811
#define MAX_USB_INTERFACES 32

typedef struct {
    uint32_t number;
    uint32_t class_code;
    uint32_t subclass;
    uint32_t protocol;
} USBInterfaceInfo;

typedef struct {
    bool network_service_attached;
    char network_service_class[128];
    USBInterfaceInfo interfaces[MAX_USB_INTERFACES];
    size_t interface_count;
} DescendantInfo;

static void usage(const char *program)
{
    printf("Usage: %s [--json] [--help]\n", program);
    puts("Detect the MindRove-branded Realtek 0x0bda:0xc811 USB adapter.");
}

static bool copy_string_property(io_registry_entry_t entry,
                                 CFStringRef key,
                                 char *destination,
                                 size_t destination_size)
{
    CFTypeRef value = IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0);
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) {
        if (value != NULL) {
            CFRelease(value);
        }
        return false;
    }

    const bool converted = CFStringGetCString((CFStringRef)value,
                                               destination,
                                               (CFIndex)destination_size,
                                               kCFStringEncodingUTF8);
    CFRelease(value);
    return converted;
}

static bool copy_u32_property(io_registry_entry_t entry, CFStringRef key, uint32_t *destination)
{
    CFTypeRef value = IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0);
    if (value == NULL || CFGetTypeID(value) != CFNumberGetTypeID()) {
        if (value != NULL) {
            CFRelease(value);
        }
        return false;
    }

    int64_t converted = 0;
    const bool success = CFNumberGetValue((CFNumberRef)value,
                                          kCFNumberSInt64Type,
                                          &converted);
    CFRelease(value);
    if (!success || converted < 0 || converted > UINT32_MAX) {
        return false;
    }

    *destination = (uint32_t)converted;
    return true;
}

static bool class_looks_like_network_service(const char *class_name)
{
    return strstr(class_name, "Network") != NULL ||
           strstr(class_name, "Ethernet") != NULL ||
           strstr(class_name, "80211") != NULL;
}

static void inspect_descendants(io_registry_entry_t device, DescendantInfo *result)
{
    io_iterator_t iterator = IO_OBJECT_NULL;
    const kern_return_t status = IORegistryEntryCreateIterator(
        device,
        kIOServicePlane,
        kIORegistryIterateRecursively,
        &iterator);
    if (status != KERN_SUCCESS) {
        return;
    }

    io_registry_entry_t child = IO_OBJECT_NULL;
    while ((child = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        io_name_t class_name = {0};
        if (IOObjectGetClass(child, class_name) == KERN_SUCCESS) {
            char bsd_name[128] = {0};
            const bool has_bsd_name = copy_string_property(child,
                                                           CFSTR("BSD Name"),
                                                           bsd_name,
                                                           sizeof(bsd_name));
            if (!result->network_service_attached &&
                (has_bsd_name || class_looks_like_network_service(class_name))) {
                result->network_service_attached = true;
                snprintf(result->network_service_class,
                         sizeof(result->network_service_class),
                         "%s",
                         class_name);
            }

            if (strcmp(class_name, "IOUSBHostInterface") == 0 &&
                result->interface_count < MAX_USB_INTERFACES) {
                USBInterfaceInfo info = {0};
                (void)copy_u32_property(child, CFSTR("bInterfaceNumber"), &info.number);
                (void)copy_u32_property(child, CFSTR("bInterfaceClass"), &info.class_code);
                (void)copy_u32_property(child, CFSTR("bInterfaceSubClass"), &info.subclass);
                (void)copy_u32_property(child, CFSTR("bInterfaceProtocol"), &info.protocol);
                result->interfaces[result->interface_count++] = info;
            }
        }
        IOObjectRelease(child);
    }

    IOObjectRelease(iterator);
}

static void print_json_string(const char *value)
{
    putchar('"');
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        switch (*cursor) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\b':
            fputs("\\b", stdout);
            break;
        case '\f':
            fputs("\\f", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (*cursor < 0x20) {
                printf("\\u%04x", *cursor);
            } else {
                putchar(*cursor);
            }
        }
    }
    putchar('"');
}

static void print_interfaces_human(const DescendantInfo *info)
{
    printf("USB interfaces: %zu\n", info->interface_count);
    for (size_t index = 0; index < info->interface_count; ++index) {
        const USBInterfaceInfo *interface = &info->interfaces[index];
        printf("  - #%u class 0x%02x, subclass 0x%02x, protocol 0x%02x\n",
               interface->number,
               interface->class_code,
               interface->subclass,
               interface->protocol);
    }
}

static void print_interfaces_json(const DescendantInfo *info)
{
    putchar('[');
    for (size_t index = 0; index < info->interface_count; ++index) {
        const USBInterfaceInfo *interface = &info->interfaces[index];
        if (index != 0) {
            putchar(',');
        }
        printf("{\"number\":%u,\"class\":%u,\"subclass\":%u,\"protocol\":%u}",
               interface->number,
               interface->class_code,
               interface->subclass,
               interface->protocol);
    }
    putchar(']');
}

static CFMutableDictionaryRef create_matching_dictionary(void)
{
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBHostDevice");
    if (matching == NULL) {
        return NULL;
    }

    int32_t vendor_id = MINDROVE_VENDOR_ID;
    int32_t product_id = MINDROVE_PRODUCT_ID;
    CFNumberRef vendor = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &vendor_id);
    CFNumberRef product = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &product_id);
    if (vendor == NULL || product == NULL) {
        if (vendor != NULL) {
            CFRelease(vendor);
        }
        if (product != NULL) {
            CFRelease(product);
        }
        CFRelease(matching);
        return NULL;
    }

    CFDictionarySetValue(matching, CFSTR("idVendor"), vendor);
    CFDictionarySetValue(matching, CFSTR("idProduct"), product);
    CFRelease(vendor);
    CFRelease(product);
    return matching;
}

int main(int argc, char **argv)
{
    bool json = false;
    if (argc == 2 && strcmp(argv[1], "--json") == 0) {
        json = true;
    } else if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(argv[0]);
        return EXIT_SUCCESS;
    } else if (argc != 1) {
        usage(argv[0]);
        return 64;
    }

    CFMutableDictionaryRef matching = create_matching_dictionary();
    if (matching == NULL) {
        fputs("Could not create an IOKit matching dictionary.\n", stderr);
        return EXIT_FAILURE;
    }

    io_iterator_t iterator = IO_OBJECT_NULL;
    const kern_return_t status = IOServiceGetMatchingServices(kIOMainPortDefault,
                                                               matching,
                                                               &iterator);
    if (status != KERN_SUCCESS) {
        fprintf(stderr, "IOKit lookup failed: 0x%x\n", status);
        return EXIT_FAILURE;
    }

    size_t device_count = 0;
    bool first_json_device = true;
    if (json) {
        printf("{\"schemaVersion\":1,\"targetVendorId\":\"0x%04x\","
               "\"targetProductId\":\"0x%04x\",\"devices\":[",
               MINDROVE_VENDOR_ID,
               MINDROVE_PRODUCT_ID);
    } else {
        puts("MindRove USB probe");
    }

    io_service_t device = IO_OBJECT_NULL;
    while ((device = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        ++device_count;
        char product[256] = "Unknown";
        char vendor[256] = "Unknown";
        (void)copy_string_property(device, CFSTR("USB Product Name"), product, sizeof(product));
        (void)copy_string_property(device, CFSTR("USB Vendor Name"), vendor, sizeof(vendor));

        DescendantInfo descendants = {0};
        inspect_descendants(device, &descendants);

        if (json) {
            if (!first_json_device) {
                putchar(',');
            }
            first_json_device = false;
            printf("{\"vendorId\":\"0x%04x\",\"productId\":\"0x%04x\","
                   "\"vendorName\":",
                   MINDROVE_VENDOR_ID,
                   MINDROVE_PRODUCT_ID);
            print_json_string(vendor);
            fputs(",\"productName\":", stdout);
            print_json_string(product);
            fputs(",\"usbInterfaces\":", stdout);
            print_interfaces_json(&descendants);
            printf(",\"networkServiceAttached\":%s",
                   descendants.network_service_attached ? "true" : "false");
            if (descendants.network_service_attached) {
                fputs(",\"networkServiceClass\":", stdout);
                print_json_string(descendants.network_service_class);
            }
            putchar('}');
        } else {
            printf("Adapter: FOUND (0x%04x:0x%04x)\n",
                   MINDROVE_VENDOR_ID,
                   MINDROVE_PRODUCT_ID);
            printf("USB name: %s / %s\n", vendor, product);
            print_interfaces_human(&descendants);
            if (descendants.network_service_attached) {
                printf("macOS network service: ATTACHED (%s)\n",
                       descendants.network_service_class);
            } else {
                puts("macOS network service: NOT ATTACHED");
                puts("Diagnosis: USB works; a compatible network driver is missing.");
            }
        }

        IOObjectRelease(device);
    }

    IOObjectRelease(iterator);

    if (json) {
        printf("],\"deviceCount\":%zu,\"adapterPresent\":%s}\n",
               device_count,
               device_count > 0 ? "true" : "false");
    } else if (device_count == 0) {
        printf("Adapter: NOT FOUND (expected 0x%04x:0x%04x)\n",
               MINDROVE_VENDOR_ID,
               MINDROVE_PRODUCT_ID);
        puts("Reconnect it directly or through a powered hub, then run the probe again.");
    }

    return device_count > 0 ? EXIT_SUCCESS : 2;
}
