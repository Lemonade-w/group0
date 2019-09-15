#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define WRITE_SIZE 512

static unsigned
min(unsigned x, unsigned y) {
    if (x < y) {
        return x;
    }
    return y;
}

static void
handle_write(uint32_t *args, uint32_t *eax) {
    int fd = (int) args[1];
    const char* buffer = (char *) args[2];
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
        PANIC("write syscall currently only supports STDOUT");
    }
}

static void handle_practice(uint32_t *args, uint32_t *eax) {
    int i = (int) args[1];
    *eax = i + 1;
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
        f->eax = args[1];
        printf("%s: exit(%d)\n", &thread_current ()->name, args[1]);
        thread_exit();
        break;

      case SYS_WRITE:
        handle_write(args, &f->eax);
        break;

      case SYS_PRACTICE:
        handle_practice(args, &f->eax);
        break;

      default:
        PANIC("Unkown syscall number %d", args[0]);
  }
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
