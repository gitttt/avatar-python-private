import logging
import subprocess
import os
import socket
from avatar.interfaces.panda_remote_memory import PandaRemoteMemoryInterface
from avatar.emulators.emulator import Emulator
import time
from avatar.util.processes import find_processes
import signal
import threading
from avatar.bintools.gdb.gdb_debugger import GdbDebugger
from avatar.bintools.gdb.mi_parser import Async
from avatar.system import EVENT_RUNNING, EVENT_STOPPED, EVENT_BREAKPOINT, EVENT_END_STEPPING
from avatar.debuggable import Breakpoint
from queue import Queue
log = logging.getLogger(__name__)

OUTPUT_DIRECTORY = "/tmp/"
# stdio/stderr of the PANDA process (QEMU)
        
# TODO: move me out to a more general place
class GDBBreakpoint(Breakpoint):
    # This is a wrapper around the python gdb wrapper
    def __init__(self, system, bkpt_num):
        super().__init__()
        self._system = system
        self._bkpt_num = bkpt_num
        self._queue = Queue()
        system.register_event_listener(self._event_receiver)
        
    def wait(self, timeout = None):
        if self._handler:
            raise Exception("Breakpoint cannot have a handler and be waited on")

        if timeout == 0:
            return self._queue.get(False)
        else:
            return self._queue.get(True, timeout)
    
    def delete(self):
        self._system.unregister_event_listener(self._event_receiver)
        self._system.get_emulator()._gdb_interface.delete_breakpoint(self._bkpt_num)
        
    def _event_receiver(self, evt):
        if EVENT_BREAKPOINT in evt["tags"] and \
                evt["source"] == "emulator" and \
                evt["properties"]["bkpt_number"] == self._bkpt_num:
            if self._handler:
                self._handler(self._system, self)
            else:
                self._queue.put(evt)

class PandaEmulator(Emulator):
    def __init__(self, system):
        super().__init__(system)
        self._configuration = None #TODO
        
    def init(self):
        log.error("Panda init called")
        #TODO: Parse configuration file, generate command line
        # to debug command the emulator
        #self._cmdline = ["gdb", "-ex", "handle SIG38 nostop noprint pass", "-ex", "run", "--args", "/home/vagrant/panda/qemu/arm-softmmu/qemu-system-arm", "-sdl", "-M", "versatilepb", "-kernel", "/home/vagrant/avatar-samples/qemu_uboot/u-boot", "-qmp", "tcp::4000,server,nowait",
                         #"-gdb", "tcp::5000,server,nowait", "-S", "-panda", "avatar_memory_hooker:range_uart0=0x101f1000_0x1000,range_uart1=0x101f2000_0x1000,range_uart2=0x101f3000_0x1000,range_uart3=0x10009000_0x1000"]
                         ## -S damit der gdb vor der ersten Instruktion abwartet pausiert.
        # Normal (non debug mode)        
        self._cmdline = ["/home/vagrant/panda/qemu/arm-softmmu/qemu-system-arm", "-sdl", "-M", "versatilepb", "-kernel", "/home/vagrant/avatar-samples/qemu_uboot/u-boot", "-qmp", "tcp::4000,server,nowait",
                                                  "-gdb", "tcp::5000,server,nowait", "-S", "-panda", "avatar_memory_hooker:range_uart0=0x101f1000_0x1000,range_uart1=0x101f2000_0x1000,range_uart2=0x101f3000_0x1000,range_uart3=0x10009000_0x1000"]
                                                  # -S damit der gdb vor der ersten Instruktion abwartet pausiert.        
        
    def start(self):
        log.info("Executing Panda process: %s", " ".join(["'%s'" % x for x in self._cmdline]))
        self._panda_thread = threading.Thread(target = self.run_panda_process)
        self._is_panda_running = threading.Event()
        self._panda_thread.start()

        #TODO: Would be nicer to put this somewhere in a function called is_running
        #so that other stuff can start in parallel and in the end the system waits for everything
        #to be running
        self._is_panda_running.wait()
        
    def stop(self):
        if hasattr(self, "_panda_process"):
            self._panda_process.kill()
            
    def exit(self):
        if hasattr(self, "_remote_memory_interface"):
            self._remote_memory_interface.stop()
            
        print("Exiting")
        
    def run_panda_process(self):
        try:
            log.info("Starting Panda process: %s", " ".join(["'%s'" % x for x in self._cmdline]))
        
            self._panda_process = subprocess.Popen(
                        self._cmdline, 
                        #cwd = self._configuration.get_output_directory(), 
                        stdout = subprocess.PIPE,
                        stderr = subprocess.PIPE)
            self._panda_stdout_tee_process = subprocess.Popen(
                    ["tee", os.path.normpath(os.path.join(OUTPUT_DIRECTORY,  "panda_stdout.log"))], 
                    stdin = self._panda_process.stdout, 
                    cwd = OUTPUT_DIRECTORY)
            self._panda_stderr_tee_process = subprocess.Popen(
                    ["tee", os.path.normpath(os.path.join(OUTPUT_DIRECTORY,  "panda_stderr.log"))], 
                    stdin = self._panda_process.stderr, 
                    cwd = OUTPUT_DIRECTORY)


            self._remote_memory_interface = PandaRemoteMemoryInterface(("127.0.0.1", 5555))
            # Uebergebe callbacks, ein callback ist z.B. self._notify_read_request_handler
            self._remote_memory_interface.set_read_handler(self._notify_read_request_handler)
            self._remote_memory_interface.set_write_handler(self._notify_write_request_handler)
            self._remote_memory_interface.set_set_cpu_state_handler(self._notify_set_cpu_state_handler)
            self._remote_memory_interface.set_get_cpu_state_handler(self._notify_get_cpu_state_handler)
            self._remote_memory_interface.set_continue_handler(self._notify_continue_handler)
            self._remote_memory_interface.set_get_checksum_handler(self._system.get_target().get_checksum)
            
            # We need some time until the sockets from the RemoteMemory plugin are open
            time.sleep(2) #Wait a bit for the Panda process to start, der socket vom Panda Plugin wird
            # tatsaechlich vor dem GDB-emulaor-server socket aufgemacht
            self._remote_memory_interface.start()
            
            # We need some time until the (potential) sockets from the QMP are open AND
            # until the QEMU-gdb-server socket is open
            time.sleep(2)
            self._monitor_socket = socket.create_connection(("127.0.0.1", 4000))

            try:
                #TODO: Path fuer GDB fuer emulator hier finden
                raise KeyError()
                #gdb_path = self._configuration._panda_configuration["emulator_gdb_path"]
            except KeyError:
                gdb_path = "arm-none-eabi-gdb"
                log.warn("Using default gdb executable path: %s" % gdb_path)
                
            
            # try:
            #     gdb_additional_args = self._configuration._panda_configuration["emulator_gdb_additional_arguments"]
            # except KeyError:
            gdb_additional_args = []

            self._gdb_interface = GdbDebugger(gdb_executable = gdb_path, cwd = ".", additional_args = gdb_additional_args)
            self._gdb_interface.set_async_message_handler(self.handle_gdb_async_message)
            count = 10
            while count != 0:
                try:
                    log.debug("Trying to connect to emulator.")
                    self._gdb_interface.connect(("tcp", "127.0.0.1", "%d" % 5000))
                    break
                except:
                    count -= 1
                    if count > 0:
                        log.warning("Failed to connect to emulator, retrying.")
                    time.sleep(3)
            if count == 0:
                raise Exception("Failed to connect to emulator. Giving up!")
            log.info("Successfully connected to emulator.")
            self._is_panda_running.set()
            self._panda_process.wait()
        except KeyboardInterrupt:
            pass
            
        self.exit()

    def enable_remote_memory():
        # TODO
        # talk over QMP to QEMU monitor and enable remote memory, i.e. activate memory callbacks in panda
        # same for disabling
        pass
    
    # uint_8, uint_16, uint_32, ... i.e. endianess etc.
    def write_typed_memory(self, address, size, data):
        self._gdb_interface.write_memory(address, size, data)

    def read_typed_memory(self, address, size):
        return self._gdb_interface.read_memory(address, size)

    def set_register(self, reg, val):
        self._gdb_interface.set_register(reg, val)

    def get_register_from_nr(self, reg_nr):
        return self._gdb_interface.get_register_from_nr(reg_nr)

    def get_register(self, reg):
        return self._gdb_interface.get_register(reg)

    def set_breakpoint(self, address, **properties):
        if "thumb" in properties:
            del properties["thumb"]
        bkpt = self._gdb_interface.insert_breakpoint(address, *properties)
        return GDBBreakpoint(self._system, int(bkpt["bkpt"]["number"]))
    def execute_gdb_command(self, cmd):
        return self._gdb_interface.execute_gdb_command(cmd)
        
    
    def cont(self):
        self._gdb_interface.cont()
        
    def stepi(self):
        self._gdb_interface.stepi()

    def send_signal(self, signalnr):
        self._gdb_interface.send_signal(signalnr)

    def handle_gdb_async_message(self, msg):
        print("Received async message: '%s'" % str(msg))
        if msg.type == Async.EXEC:
            if msg.klass == "running":
                self.post_event({"tags": [EVENT_RUNNING], "channel": "gdb"})
            elif msg.klass == "stopped":
                if "reason" in msg.results and msg.results["reason"] == "breakpoint-hit":
                    self.post_event({"tags": [EVENT_STOPPED, EVENT_BREAKPOINT],
                                     "properties": {
                                        "address": int(msg.results["frame"]["addr"], 16),
                                        "bkpt_number": int(msg.results["bkptno"])},
                                     "channel": "gdb"})
                elif "reason" in msg.results and msg.results["reason"] == "end-stepping-range":
                    self.post_event({"tags": [EVENT_STOPPED, EVENT_END_STEPPING],
                                     "properties": {
                                        "address": int(msg.results["frame"]["addr"], 16)
                                        },
                                     "channel": "gdb"})
                # elif "signal-name" in msg.results and msg.results["signal-name"] == "SIGINT":
                #     self.post_event({"tags": [EVENT_STOPPED, EVENT_END_STEPPING],
                #                      "properties": {
                #                         "address": int(msg.results["frame"]["addr"], 16)
                #                         },
                #                      "channel": "gdb"})
                
    def post_event(self, evt):
        evt["source"] = "emulator"
        self._system.post_event(evt)
        

def init_panda_emulator(system):
    system.set_emulator(PandaEmulator(system))
    
    
