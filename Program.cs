using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Text;

namespace GetUserSid
{
    internal class Program
    {
        const int NO_ERROR = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        const int ERROR_INVALID_FLAGS = 1004;

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupAccountName(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid([MarshalAs(UnmanagedType.LPArray)] byte[] pSID,out IntPtr ptrSid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        };

        enum FORMAT_MESSAGE : uint
        {
            ALLOCATE_BUFFER = 0x00000100,
            IGNORE_INSERTS = 0x00000200,
            FROM_SYSTEM = 0x00001000,
            ARGUMENT_ARRAY = 0x00002000,
            FROM_HMODULE = 0x00000800,
            FROM_STRING = 0x00000400
        };

        static void Main(string[] args)
        {
            Console.WriteLine($"GetUserSid, by Hannah Vernon, v{System.Reflection.Assembly.GetExecutingAssembly().GetName().Version:s}");
            if (args.Length == 0)
            {
                Console.WriteLine();
                Console.WriteLine("Usage is: GetUserSid <username>");
            }
            else
            {
                var accountName = args[0];
                string? systemName = null;
                byte[]? sid = null;
                uint cbSid = 0;
                StringBuilder referencedDomainName = new StringBuilder();
                uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
                SID_NAME_USE sidUse;
                int err = NO_ERROR;
                IntPtr ptrSid;

                if (!LookupAccountName(systemName, accountName, sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                {
                    err = Marshal.GetLastWin32Error();
                    if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_INVALID_FLAGS)
                    {
                        sid = new byte[cbSid];
                        referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                        err = NO_ERROR;
                        if (!LookupAccountName(systemName, accountName, sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        {
                            err = Marshal.GetLastWin32Error();
                        };
                    };
                }
                else
                {
                    Console.WriteLine($"{accountName} not found.");
                }
                if (err == NO_ERROR)
                {
                    if (!ConvertSidToStringSid(sid, out ptrSid))
                    {
                        err = Marshal.GetLastWin32Error();
                        Console.WriteLine(@"Could not convert Security Identifier to string. Error : {0}", err);
                    }
                    else
                    {
                        string? sidString = Marshal.PtrToStringAuto(ptrSid);
                        LocalFree(ptrSid);
                        Console.WriteLine(@"{0} has a type of {1}.  The Security Identifier is {2}", accountName, sidUse, sidString);
                    }
                }
                else
                {
                    var msg = new Win32Exception(err).Message;
                    Console.WriteLine($"{msg}");
                };
            };
        }
    };
};