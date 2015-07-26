/**************************************************************************
Copyright(C) 2011-2015 Ian Farr

This file is part of Farrworks.Net.dll

Farrworks.Net.dll is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or(at your option) any later version.

Farrworks.Net.dll is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; If not, see <http://www.gnu.org/licenses/>
**************************************************************************/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Farrworks.Net
{
    //usefull links:
    // http://www.pinvoke.net/
    // http://msdn.microsoft.com/en-us/library/ms681381(v=vs.85).aspx // system error codes
    // http://msdn.microsoft.com/en-us/library/aa370674(v=vs.85).aspx // network management error codes
    internal class NativeMethods
    {
        #region constants

        internal const uint STYPE_DISKTREE = 0;
        internal const uint SECURITY_DESCRIPTOR_REVISION = 1;
        internal const uint NO_INHERITANCE = 0;
        internal const uint ERROR_NONE_MAPPED = 1332;

        #endregion
        
        #region  enums
        internal enum NET_API_STATUS : uint
        {
            NERR_Success = 0,
            ERROR_ACCESS_DENIED = 5,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_BAD_NETPATH = 53,
            ERROR_INVALID_NAME = 123,
            ERROR_INVALID_LEVEL = 124,
            NERR_UnknownDevDir = 2116,
            NERR_RedirectedPath = 2117,
            NERR_DuplicateShare = 2118,
            NERR_BufTooSmall = 2123,
            NERR_ShareDoesNotExist = 2310,
        }

        internal enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }

        internal enum ACCESS_MASK : uint
        {
            LM_SHARE_READ = 1179817,
            LM_SHARE_CHANGE = 1245631,
            LM_SHARE_ALL = 2032127,
            GENERIC_ALL = 268435456,
            GENERIC_READ = 2147483648,
            GENERIC_WRITE = 1073741824,
            GENERIC_EXECUTE = 536870912,
            STANDARD_RIGHTS_READ = 131072,
        }

        internal enum ACCESS_MODE : uint
        {
            NOT_USED_ACCESS = 0,
            GRANT_ACCESS = 1,
            SET_ACCESS = 2,
            DENY_ACCESS = 3,
            REVOKE_ACCESS = 4,
            SET_AUDIT_SUCCESS = 5,
            SET_AUDIT_FAILURE = 6,
        }

        internal enum TRUSTEE_FORM : uint
        {
            TRUSTEE_IS_SID = 0,
            TRUSTEE_IS_NAME = 1,
            TRUSTEE_BAD_FORM = 2,
            TRUSTEE_IS_OBJECTS_AND_SID = 3,
            TRUSTEE_IS_OBJECTS_AND_NAME = 4,
        }

        internal enum TRUSTEE_TYPE : uint
        {
            TRUSTEE_IS_UNKNOWN = 0,
            TRUSTEE_IS_USER = 1,
            TRUSTEE_IS_GROUP = 2,
            TRUSTEE_IS_DOMAIN = 3,
            TRUSTEE_IS_ALIAS = 4,
            TRUSTEE_IS_WELL_KNOWN_GROUP = 5,
            TRUSTEE_IS_DELETED = 6,
            TRUSTEE_IS_INVALID = 7,
            TRUSTEE_IS_COMPUTER = 8,
        }

        internal enum MULTIPLE_TRUSTEE_OPERATION : uint
        {
            NO_MULTIPLE_TRUSTEE = 0,
            TRUSTEE_IS_IMPERSONATE = 1,
        }
        #endregion

        #region structures
        // http://msdn.microsoft.com/en-us/library/bb525410(VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct SHARE_INFO_502
        {
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string shi502_netname;
            internal uint shi502_type;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string shi502_remark;
            internal int shi502_permissions;
            internal int shi502_max_uses;
            internal int shi502_current_uses;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string shi502_path;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string shi502_passwd;
            internal int shi502_reserved;
            internal IntPtr shi502_security_descriptor;
        }

        // http://msdn.microsoft.com/en-us/library/bb525404(v=VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct SHARE_INFO_1005
        {
            internal uint shi1005_flags;
        }

        // initialized by InitializeSecurityDescriptor: http://msdn.microsoft.com/en-us/library/aa378863(VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_DESCRIPTOR
        {
            internal byte Revision;
            internal byte Sbz1;
            internal ushort Control;
            internal IntPtr Owner;
            internal IntPtr Group;
            internal IntPtr Sacl;
            internal IntPtr Dacl;
        }

        // http://msdn.microsoft.com/en-us/library/aa379636(v=VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct TRUSTEE
        {
            internal uint pMultipleTrustee;
            internal MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            internal TRUSTEE_FORM TrusteeForm;
            internal TRUSTEE_TYPE TrusteeType;
            [MarshalAsAttribute(UnmanagedType.LPTStr)]
            internal string ptstrName;
        }

        // http://msdn.microsoft.com/en-us/library/aa446627(VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct EXPLICIT_ACCESS
        {
            internal uint grfAccessPermissions;
            internal ACCESS_MODE grfAccessMode;
            internal uint grfInheritance;
            internal TRUSTEE Trustee;
        }

        // http://msdn.microsoft.com/en-us/library/bb524796(VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct DFS_STORAGE_INFO
        {
            internal uint State;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string ServerName;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string ShareName;
        }

        // http://msdn.microsoft.com/en-us/library/bb524790(VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        internal struct DFS_INFO_3
        {
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string EntryPath;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            internal string Comment;
            internal uint State;
            internal uint NumberOfStorages;
            internal uint Storage;
        }
        #endregion

        #region Win32Imports
        // http://msdn.microsoft.com/en-us/library/bb525384(VS.85).aspx
        [DllImportAttribute("netapi32.dll", EntryPoint = "NetShareAdd", CharSet = CharSet.Unicode)]
        internal static extern NET_API_STATUS NetShareAdd(
            [MarshalAsAttribute(UnmanagedType.LPWStr)] string servername,
            uint level,
            ref SHARE_INFO_502 buf,
            ref int parm_err);

        // http://msdn.microsoft.com/en-us/library/aa378863(VS.85).aspx
        [DllImportAttribute("advapi32.dll", EntryPoint = "InitializeSecurityDescriptor")]
        internal static extern uint InitializeSecurityDescriptor(
            ref SECURITY_DESCRIPTOR pSecurityDescriptor, 
            uint dwRevision);

        // http://msdn.microsoft.com/en-us/library/aa379576(VS.85).aspx
        [DllImportAttribute("advapi32.dll", EntryPoint = "SetEntriesInAclW")]
        internal static extern uint SetEntriesInAcl(
            int cCountOfExplicitEntries,
            [InAttribute()] ref EXPLICIT_ACCESS pListOfExplicitEntries, 
            [InAttribute()] System.IntPtr OldAcl, 
            ref System.IntPtr NewAcl);

        // http://msdn.microsoft.com/en-us/library/aa379583(VS.85).aspx
        [DllImportAttribute("advapi32.dll", EntryPoint = "SetSecurityDescriptorDacl")]
        internal static extern uint SetSecurityDescriptorDacl(
            ref SECURITY_DESCRIPTOR pSecurityDescriptor, 
            [MarshalAsAttribute(UnmanagedType.Bool)]bool bDaclPresent, 
            [InAttribute()] System.IntPtr pDacl, 
            [MarshalAsAttribute(UnmanagedType.Bool)]bool bDaclDefaulted);

        // http://msdn.microsoft.com/en-us/library/aa379147(VS.85).aspx
        [DllImportAttribute("advapi32.dll", EntryPoint = "IsValidSecurityDescriptor")]
        internal static extern uint IsValidSecurityDesctiptor(ref SECURITY_DESCRIPTOR pSecurityDescriptor);

        // http://msdn.microsoft.com/en-us/library/bb525388(VS.85).aspx
        [DllImport("Netapi32.dll", SetLastError = true)]
        internal static extern int NetShareGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            [MarshalAs(UnmanagedType.LPWStr)] string netName,
            Int32 level,
            out IntPtr bufPtr
        );

        // http://msdn.microsoft.com/en-us/library/bb525389(v=VS.85).aspx
        [DllImport("Netapi32.dll", SetLastError = true)]
        internal static extern int NetShareSetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            [MarshalAs(UnmanagedType.LPWStr)] string netName,
            uint level,
            IntPtr buf,
            out IntPtr parm_err
        );

        // http://msdn.microsoft.com/en-us/library/bb524812(v=VS.85).aspx
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int NetDfsGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string DfsEntryPath,
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,    //should be set to null..ignored: http://msdn.microsoft.com/en-us/library/bb524812(v=VS.85).aspx
            [MarshalAs(UnmanagedType.LPWStr)] string ShareName,     //should be set to null..ignored: http://msdn.microsoft.com/en-us/library/bb524812(v=VS.85).aspx
            int Level,
            out IntPtr Buffer
        );

        // http://msdn.microsoft.com/en-us/library/bb524817(v=VS.85).aspx
        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int NetDfsRemove(
          [MarshalAs(UnmanagedType.LPWStr)] string DfsEntryPath,
          [MarshalAs(UnmanagedType.LPWStr)] string ServerName,      //optional - can be null
          [MarshalAs(UnmanagedType.LPWStr)] string ShareName        //optional - can be null - if both servername and sharename are null, then the dfsentrypath is removed completely.
        );

        // http://msdn.microsoft.com/en-us/library/bb524805(v=VS.85).aspx
        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int NetDfsAdd(
            [MarshalAs(UnmanagedType.LPWStr)] string DfsEntryPath,
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [MarshalAs(UnmanagedType.LPWStr)] string PathName,
            [MarshalAs(UnmanagedType.LPWStr)] string Comment,
            int Flags // specify 0 for no flags, or else specify 1 for DFS_ADD_VOLUME
        );

        // http://msdn.microsoft.com/en-us/library/aa370304(VS.85).aspx
        [DllImport("Netapi32")]
        internal static extern uint NetApiBufferFree(IntPtr Buffer);
        #endregion
    }
}
