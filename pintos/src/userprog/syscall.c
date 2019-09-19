#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define WRITE_SIZE 512
#define FD_OFFSET 2

typedef int pid_t;

struct lock filesys_mutex;

static unsigned min(unsigned x, unsigned y) {
    if (x < y) {
        return x;
    }
    return y;
}

static void validate_all_args(uint32_t *args, size_t n_args) {
    if ((uint32_t) args > (uint32_t) PHYS_BASE - sizeof(uint32_t) * n_args) {
        thread_exit(-1);
    }
}

static void validate_ptr_arg(const void *ptr) {
    if (ptr == NULL) {
        thread_exit(-1);
    } else if ((uint32_t)ptr >= (uint32_t)PHYS_BASE) {
        thread_exit(-1);
    }
}

static void
handle_write(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 4);
    int fd = (int) args[1];
    if (fd >= MAX_FDS || fd == 0) {
        *eax = -1;
        return;
    }
    const char* buffer = (char *) args[2];
    validate_ptr_arg(buffer);
    unsigned size = (unsigned) args[3];

    if (fd == 1) { // STDOUT
        unsigned written = 0;
        while (written < size) {
            unsigned n = min(size - written, WRITE_SIZE);
            putbuf(buffer + written, n);
            written += n;
        }

        *eax = written;
    } else {
        struct thread *current = thread_current();
        struct file* file = current->open_files[fd];
        if (file == NULL) {
            *eax = -1;
            return;
        }
        *eax = file_write(file, buffer, size);
    }
}

static void
handle_read(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 4);
    int fd = (int)args[1];
    if (fd >= MAX_FDS || fd == 1) {
        *eax = -1;
        return;
    }
    char *buffer = (char *)args[2];
    validate_ptr_arg(buffer);
    unsigned size = (unsigned) args[3];

    if (fd == 0) { // STDIN
        unsigned read = 0;
        while (read < size) {
            buffer[read] = input_getc();
            read++;
        }

        *eax = read;
    } else {
        struct thread *current = thread_current();
        struct file *file = current->open_files[fd];
        if (file == NULL) {
            *eax = -1;
            return;
        }
        *eax = file_read(file, buffer, size);
    }
}

static void handle_practice(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 2);
    int i = (int) args[1];
    *eax = i + 1;
}

static void handle_shutdown(__attribute__ ((unused)) uint32_t *args,
                            __attribute__ ((unused)) uint32_t *eax) {
    shutdown_power_off();
}

static void handle_exec(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 2);
    char *cmd_line = (char *)args[1];
    tid_t thread_id = process_execute(cmd_line);
    if (thread_id == TID_ERROR) {
        *eax = -1;
    } else {
        *eax = thread_id;
    }
}

static void handle_wait(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 2);
    int pid = (int) args[1];
    *eax = process_wait(pid);
}

static void handle_create(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 3);
    char *file = (char *)args[1];
    validate_ptr_arg(file);
    unsigned initial_size = (unsigned)args[2];

    lock_acquire(&filesys_mutex);
    *eax = filesys_create(file, initial_size);
    lock_release(&filesys_mutex);
}

static void handle_remove(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 2);
    char *file = (char *)args[1];
    validate_ptr_arg(file);

    lock_acquire(&filesys_mutex);
    *eax = filesys_remove(file);
    lock_release(&filesys_mutex);
}

static void handle_open(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 2);
    char *file_name = (char *)args[1];
    validate_ptr_arg(file_name);

    lock_acquire(&filesys_mutex);
    struct file *file = filesys_open(file_name);
    lock_release(&filesys_mutex);

    if (file == NULL) {
        *eax = -1;
        return;
    }

    struct thread *cur = thread_current();
    int fd = cur->next_file_slot;
    while ((uint32_t) (cur->open_files[fd]) == RESERVED_FILE || cur->open_files[fd] != NULL) {
        fd++;
    }
    cur->open_files[fd] = file;
    cur->next_file_slot = fd + 1;
    *eax = fd;
}

static void handle_close(uint32_t *args, __attribute__ ((unused)) uint32_t *eax) {
    validate_all_args(args, 2);
    int fd = (int)args[1];
    if (fd >= MAX_FDS) {
        thread_exit(-1);
    }

    struct thread *current = thread_current();
    struct file *file = current->open_files[fd];
    if (file == NULL || (uint32_t)file == RESERVED_FILE) {
        thread_exit(-1);
    }

    lock_acquire(&filesys_mutex);
    file_close(file);
    lock_release(&filesys_mutex);
    current->open_files[fd] = NULL;
}

static void handle_filesize(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 2);
    int fd = (int)args[1];
    if (fd >= MAX_FDS) {
        *eax = -1;
        return;
    }

    struct thread *current = thread_current();
    struct file *file = current->open_files[fd];
    if (file == NULL || (uint32_t)file == RESERVED_FILE) {
        *eax = -1;
        return;
    }

    lock_acquire(&filesys_mutex);
    *eax = file_length(file);
    lock_release(&filesys_mutex);
}

static void handle_tell(uint32_t *args, uint32_t *eax) {
    validate_all_args(args, 2);
    int fd = (int)args[1];
    if (fd >= MAX_FDS) {
        *eax = -1;
        return;
    }

    struct thread *current = thread_current();
    struct file *file = current->open_files[fd];
    if (file == NULL || (uint32_t)file == RESERVED_FILE) {
        *eax = -1;
        return;
    }

    lock_acquire(&filesys_mutex);
    *eax = file_tell(file);
    lock_release(&filesys_mutex);
}

static void handle_seek(uint32_t *args, __attribute__ ((unused)) uint32_t *eax) {
    validate_all_args(args, 3);
    int fd = (int)args[1];
    if (fd >= MAX_FDS) {
        thread_exit(-1);
    }
    unsigned position = (unsigned)args[2];

    struct thread *current = thread_current();
    struct file *file = current->open_files[fd];
    if (file == NULL || (uint32_t)file == RESERVED_FILE) {
        thread_exit(-1);
    }

    lock_acquire(&filesys_mutex);
    file_seek(file, position);
    lock_release(&filesys_mutex);
}

static void
syscall_handler (struct intr_frame *f)
{
  uint32_t* args = ((uint32_t*) f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  switch (args[0]) {
      case SYS_EXIT:
        validate_all_args(args, 2);
        f->eax = args[1];
        thread_exit(args[1]);
        break;

      case SYS_WRITE:
        handle_write(args, &f->eax);
        break;

      case SYS_READ:
        handle_read(args, &f->eax);
        break;

      case SYS_PRACTICE:
        handle_practice(args, &f->eax);
        break;

      case SYS_HALT:
        handle_shutdown(args, &f->eax);
        break;

      case SYS_EXEC:
        handle_exec(args, &f->eax);
        break;

      case SYS_WAIT:
        handle_wait(args, &f->eax);
        break;

      case SYS_CREATE:
        handle_create(args, &f->eax);
        break;

      case SYS_REMOVE:
        handle_remove(args, &f->eax);
        break;

      case SYS_OPEN:
        handle_open(args, &f->eax);
        break;

      case SYS_CLOSE:
        handle_close(args, &f->eax);
        break;

    case SYS_SEEK:
        handle_seek(args, &f->eax);
        break;

    case SYS_TELL:
        handle_tell(args, &f->eax);
        break;

    case SYS_FILESIZE:
        handle_filesize(args, &f->eax);
        break;

      default:
        PANIC("Unkown syscall number %d", args[0]);
  }
}

void
syscall_init (void)
{
  lock_init(&filesys_mutex);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
