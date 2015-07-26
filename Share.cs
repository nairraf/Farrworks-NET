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

namespace Farrworks.Net
{
    public static class Share
    {
        #region enums
        /// <summary>
        /// enum which holds values for the statue of a share (Is shared, is not shared, is duplicate share)
        /// </summary>
        public enum State
        {
            IsShared = 0,
            IsNotShared = 1,
            IsDuplicateShare = 2,
        }

        /// <summary>
        /// enum used to standardize share permissions
        /// </summary>
        public enum Permission
        {
            Read = 0,
            Change = 1,
            FullControl = 2,
        }

        /// <summary>
        /// enum to standardize if we grant or deny the share permission
        /// </summary>
        public enum Action
        {
            Allow = 0,
            Deny = 1,
        }

        public enum ShareStatus
        {
            Success = 0,
            Err_DuplicateShare = 1,
            Err_PathNotFound = 2,
            Err_UnknownError = 3,
            Err_Invalid_Security_Descriptor = 4,
            Err_Security_Descriptor_Init = 5,
            Err_Invalid_SID_Mapping = 6,
            Err_Network_Path_Not_Found = 7,
        }

        public enum ShareType
        {
            Normal = 0,
            Special = 1,
        }

        // http://msdn.microsoft.com/en-us/library/bb525404(v=VS.85).aspx
        public enum CSCType
        {
            CSC_CACHE_MANUAL_REINT = 0,
            CSC_CACHE_VDO = 32,
            CSC_CACHE_AUTO_REINT = 16,
            CSC_CACHE_NONE = 48,
        }
        #endregion

        #region structures
        public struct ACL
        {
            public string DomainName;
            public string AccountName;
            public Share.Action Action;
            public Share.Permission Permission;

            public ACL(string domainName, string accountName, Share.Action action, Share.Permission permission)
            {
                this.DomainName = domainName;
                this.AccountName = accountName;
                this.Action = action;
                this.Permission = permission;
            }

            public ACL(string accountName, Share.Action action, Share.Permission permission)
            {
                this.DomainName = null;
                this.AccountName = accountName;
                this.Action = action;
                this.Permission = permission;
            }

            public string GetFullAccountName()
            {
                string ret = null;

                if (DomainName == null)
                {
                    ret = AccountName;
                }
                else
                {
                    ret = String.Format(@"{0}\{1}", DomainName, AccountName);
                }

                return ret;
            }
        }
        #endregion

        #region public_methods
        /// <summary>
        ///     Creates a share for the specified path via win32 API. Shares are created with Everyone Full Control - use NTFS to secure it!
        /// </summary>
        /// <param name="server">the server name, pass null to use the local machine</param>
        /// <param name="path">the path to the folder to share</param>
        /// <param name="shareName">what the share should be called</param>
        /// <param name="shareDesc">a description for the share</param>
        /// <param name="type">the type of share (normal or special admin hidden share). use ShareType enum</param>
        /// <param name="SharePermissions">a list of ShareACL structures which define the share permissions for this share</param>
        /// <returns>Share.ShareStatus</returns>
        public static Share.ShareStatus CreateWin32Share(string server, string path, string shareName, string shareDesc, ShareType type, List<ACL> SharePermissions)
        {
            //this will be filled by the SetEntriesInAcl Win32 call below with our ACL
            IntPtr AclPtr = IntPtr.Zero;
            
            //create the explicit access rule...this holds all our ShareACL's
            NativeMethods.EXPLICIT_ACCESS[] explicitAccessRule = new NativeMethods.EXPLICIT_ACCESS[SharePermissions.Count];

            //loop through our share permission list, and create our ACL for the share
            for (int i = 0; i < explicitAccessRule.Length; i++)
            {
                //System.Security.Principal.NTAccount ADObject = new System.Security.Principal.NTAccount(SharePermissions[i].GetFullAccountName());

                //this is how we get a sid from an account...left here in case we need it in the future
                //SecurityIdentifier ADObjectSID = (SecurityIdentifier)ADObject.Translate(typeof(SecurityIdentifier));

                //create the trustee for this user
                NativeMethods.TRUSTEE account = new NativeMethods.TRUSTEE();
                account.MultipleTrusteeOperation = NativeMethods.MULTIPLE_TRUSTEE_OPERATION.NO_MULTIPLE_TRUSTEE;
                account.pMultipleTrustee = 0;
                account.TrusteeForm = NativeMethods.TRUSTEE_FORM.TRUSTEE_IS_NAME;
                account.ptstrName = SharePermissions[i].GetFullAccountName();
                account.TrusteeType = NativeMethods.TRUSTEE_TYPE.TRUSTEE_IS_UNKNOWN; //let the win32 api figure out if it's a user or group...

                //set to allow or deny
                if (SharePermissions[i].Action == Share.Action.Allow)
                    explicitAccessRule[i].grfAccessMode = NativeMethods.ACCESS_MODE.GRANT_ACCESS;
                else
                    explicitAccessRule[i].grfAccessMode = NativeMethods.ACCESS_MODE.DENY_ACCESS;

                //build the permission
                if (SharePermissions[i].Permission == Share.Permission.Read)
                    explicitAccessRule[i].grfAccessPermissions = (uint)NativeMethods.ACCESS_MASK.LM_SHARE_READ;
                else if (SharePermissions[i].Permission == Share.Permission.Change)
                    explicitAccessRule[i].grfAccessPermissions = (uint)NativeMethods.ACCESS_MASK.LM_SHARE_CHANGE;
                else if (SharePermissions[i].Permission == Share.Permission.FullControl)
                    explicitAccessRule[i].grfAccessPermissions = (uint)NativeMethods.ACCESS_MASK.LM_SHARE_ALL;

                //assign the trustee to the access rule
                explicitAccessRule[i].grfInheritance = 0; //no inheritance, shares don't use inheritance
                explicitAccessRule[i].Trustee = account;

                //set the access rule in the ACL (which adds it to our AclPtr)
                uint setEntriesResult = NativeMethods.SetEntriesInAcl(1, ref explicitAccessRule[i], AclPtr, ref AclPtr);
                if (setEntriesResult != 0)
                    return ShareStatus.Err_Invalid_SID_Mapping;
            }

            //our default security descriptor pointer (points to zero) for now
            IntPtr secDescPtr = IntPtr.Zero;

            //create our security descriptor
            NativeMethods.SECURITY_DESCRIPTOR secDesc = new NativeMethods.SECURITY_DESCRIPTOR();
            secDesc.Revision = (byte)NativeMethods.SECURITY_DESCRIPTOR_REVISION;

            //initialize the security descriptor
            uint descriptorInit = NativeMethods.InitializeSecurityDescriptor(ref secDesc, NativeMethods.SECURITY_DESCRIPTOR_REVISION);

            //for some reason Microsoft decided that a zero return code for InitializeSecurityDescriptor means failure...go figure
            //the msdn page reads: "returns 0 on failure and non-zero on success"
            //it seems to always return 1 on success...we test that for now
            //I feel that is saffer then testing for 0 for fail and a catch-all else statement for success...we don't know if that is really true...
            //http://msdn.microsoft.com/en-us/library/aa378863(v=vs.85).aspx
            if (descriptorInit == 1)
            {
                //add the acl to the security descriptor
                uint setSecurityResult = NativeMethods.SetSecurityDescriptorDacl(ref secDesc, true, AclPtr, false);

                //returns 0 on failure...
                //http://msdn.microsoft.com/en-us/library/aa379583(v=VS.85).aspx
                if (setSecurityResult == 1)
                {

                    //last check to make sure our security descriptor is good...
                    uint isValidSD = NativeMethods.IsValidSecurityDesctiptor(ref secDesc);

                    //returns 0 on failure...
                    //http://msdn.microsoft.com/en-us/library/aa379147(v=VS.85).aspx
                    if (isValidSD == 1)
                    {
                        //security descritor looks good..point our pointer to it
                        //note - this is unmanaged memory, we have to manually clear it below when we are finished with it!
                        secDescPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(secDesc));
                        Marshal.StructureToPtr(secDesc, secDescPtr, false);
                    }
                    else
                    {
                        return Share.ShareStatus.Err_Invalid_Security_Descriptor;
                    }
                }
                else
                {
                    return Share.ShareStatus.Err_Invalid_Security_Descriptor;
                }
            }
            else
            {
                return Share.ShareStatus.Err_Security_Descriptor_Init;
            }

            //create the barebones 502 share info structure..
            NativeMethods.SHARE_INFO_502 shInfo = new NativeMethods.SHARE_INFO_502();

            //populate our 502 share info structure
            shInfo.shi502_netname = shareName;
            
            shInfo.shi502_permissions = 0; // ignored for user-level sercurity
            shInfo.shi502_path = path;
            shInfo.shi502_passwd = null; // ignored for user-level security
            shInfo.shi502_remark = shareDesc;
            shInfo.shi502_max_uses = -1;

            //what type of share should we create?
            if (type == ShareType.Normal)
                shInfo.shi502_type = (uint)NativeMethods.SHARE_TYPE.STYPE_DISKTREE;
            else if (type == ShareType.Special)
                shInfo.shi502_type = (uint)NativeMethods.SHARE_TYPE.STYPE_SPECIAL;

            //assign our new shiny security descriptor to our share_info_502 object
            shInfo.shi502_security_descriptor = secDescPtr;

            // Call the win32 Net API to add the share..
            int error = 0;
            NativeMethods.NET_API_STATUS nRetValue = NativeMethods.NetShareAdd(server, 502, ref shInfo, ref error);

            //free up our security descriptor and acl memory allocations
            //because these are non-managed memory locations, we must do this manually
            Marshal.FreeHGlobal(secDescPtr);
            Marshal.FreeHGlobal(AclPtr);

            Share.ShareStatus ret;

            switch (nRetValue)
            {
                case NativeMethods.NET_API_STATUS.NERR_Success:
                    ret = ShareStatus.Success;
                    break;
                case NativeMethods.NET_API_STATUS.NERR_UnknownDevDir:
                    ret = ShareStatus.Err_PathNotFound;
                    break;
                case NativeMethods.NET_API_STATUS.NERR_DuplicateShare:
                    ret = ShareStatus.Err_DuplicateShare;
                    break;
                case NativeMethods.NET_API_STATUS.ERROR_BAD_NETPATH:
                    ret = ShareStatus.Err_Network_Path_Not_Found;
                    break;
                default:
                    ret = ShareStatus.Err_UnknownError;
                    break;
            }

            return ret;
        }


        /// <summary>
        ///     Checks to see if a given share is shared or not. 
        ///     The share path returned by the share must match the given FullPath.
        /// </summary>
        /// <param name="serverName"></param>
        /// <param name="shareName"></param>
        /// <param name="fullPath"></param>
        /// <returns>SharedFolderState</returns>
        public static Share.State IsShared(string serverName, string shareName, string fullPath)
        {
            //by default we say that the folder is not shared
            Share.State sfs = Share.State.IsNotShared;

            //check the share
            IntPtr ptr = IntPtr.Zero;
            int errCode = NativeMethods.NetShareGetInfo(serverName, shareName, 502, out ptr);

            if ((NativeMethods.NET_API_STATUS)errCode == NativeMethods.NET_API_STATUS.NERR_Success)
            {
                //share exists at the unc path..check the returned unc path's path to the passed fullPath

                //Compare the path's - make sure they are the same
                NativeMethods.SHARE_INFO_502 shareInfo = new NativeMethods.SHARE_INFO_502();
                shareInfo = (NativeMethods.SHARE_INFO_502)Marshal.PtrToStructure(ptr, typeof(NativeMethods.SHARE_INFO_502));
                if (shareInfo.shi502_path.ToLower() == fullPath.ToLower())
                {
                    //paths are the same - mark it as shared
                    sfs = Share.State.IsShared;
                }
                else
                {
                    //paths are different - mark it as a duplicate share name!
                    sfs = Share.State.IsDuplicateShare;
                }

                //clear out the unmanaged ptr - if errCode = true, Win32's NetShareGetInfo() fills in the ptr with a structure compatible with NativeMethods.SHARE_INFO_502
                Marshal.FreeHGlobal(ptr);
            }

            return sfs;
        }
        #endregion

        public static bool SetShareCSC(string server, string shareName, CSCType cscState)
        {
            bool ret = false;
            NativeMethods.SHARE_INFO_1005 share_info_1005 = new NativeMethods.SHARE_INFO_1005();
            share_info_1005.shi1005_flags = (uint)cscState;

            IntPtr parm_err = IntPtr.Zero;
            IntPtr share_info_1005_ptr = IntPtr.Zero;

            share_info_1005_ptr = Marshal.AllocCoTaskMem(Marshal.SizeOf(share_info_1005));
            Marshal.StructureToPtr(share_info_1005, share_info_1005_ptr, false);

            int retVal = NativeMethods.NetShareSetInfo(server, shareName, 1005, share_info_1005_ptr, out parm_err);

            if (retVal == 0)
                ret = true;

            //free up our non-managed memory
            NativeMethods.NetApiBufferFree(share_info_1005_ptr);
            NativeMethods.NetApiBufferFree(parm_err);

            return ret;
        }

        public static CSCType GetShareCSCState(string server, string shareName)
        {
            CSCType curCscType = CSCType.CSC_CACHE_NONE;
            //check the share
            IntPtr ptr = IntPtr.Zero;
            int errCode = NativeMethods.NetShareGetInfo(server, shareName, 1005, out ptr);

            if ((NativeMethods.NET_API_STATUS)errCode == NativeMethods.NET_API_STATUS.NERR_Success)
            {
                //get the share_info_1005 structure
                NativeMethods.SHARE_INFO_1005 shareInfo = new NativeMethods.SHARE_INFO_1005();
                shareInfo = (NativeMethods.SHARE_INFO_1005)Marshal.PtrToStructure(ptr, typeof(NativeMethods.SHARE_INFO_1005));

                curCscType = (CSCType)shareInfo.shi1005_flags;

                //clear out the unmanaged ptr - if errCode = true, Win32's NetShareGetInfo() fills in the ptr with a structure compatible with NativeMethods.SHARE_INFO_502
                Marshal.FreeHGlobal(ptr);
            }

            return curCscType;
        }
    }
}
