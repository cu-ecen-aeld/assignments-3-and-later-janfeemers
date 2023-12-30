/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer implementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif
#include <assert.h>

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset. Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
                                                                          size_t char_offset, size_t *entry_offset_byte_rtn)
{
    assert(buffer != NULL);
    size_t counter = 0;
    size_t counter_base = 0;
    struct aesd_buffer_entry *retValue = NULL;
    for (uint8_t i = 0; i < (uint8_t)AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        const uint8_t buf_index = (buffer->out_offs + i) % (uint8_t)AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        counter += buffer->entry[buf_index].size;
        if (counter >= (char_offset+1))
        {
            const size_t element_offset = char_offset - counter_base;
            *entry_offset_byte_rtn = element_offset;
            retValue = &(buffer->entry[buf_index]);
            break;
        }
        counter_base = counter;
    }
    return retValue;
}

/**
 * Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
 * If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
 * new start location.
 * Any necessary locking must be handled by the caller
 * Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
 */
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    assert(buffer != NULL);
    assert(add_entry != NULL);

    memcpy(&(buffer->entry[buffer->in_offs]), add_entry, sizeof(struct aesd_buffer_entry));
    buffer->in_offs = (buffer->in_offs + 1) % (uint8_t)AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (buffer->full == true)
    {
        buffer->out_offs = buffer->in_offs;
    }
    else
    {
        // check if buffer is now full
        if (buffer->in_offs == buffer->out_offs)
        {
            buffer->full = true;
        }
    }
}

/**
 * Initializes the circular buffer described by @param buffer to an empty struct
 */
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    assert(buffer != NULL);
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}
