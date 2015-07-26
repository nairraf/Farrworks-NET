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
    public static class Dfs
    {
        #region enums
        public enum DFSActionStatus
        {
            Success = 0,
            Error = 1,
            Error_Duplicate = 2,
            Error_NetworkPathNotFound = 3,
        }

        public enum DFS_TARGET_STATE
        {
            DFS_STORAGE_STATE_OFFLINE = 1,
            DFS_STORAGE_STATE_ONLINE = 2,
            DFS_STORAGE_STATE_ACTIVE = 4,
        }
        #endregion


        #region structures
        public struct DfsShareDetails
        {
            public bool linkExists;
            public bool targetMatch;
            public int numberOfTargets;
            public List<DfsTarget> targets;
        }

        public struct DfsTarget
        {
            public string targetPath;
            public DFS_TARGET_STATE targetStatus;
        }
        #endregion



        #region public methods
        /// <summary>
        /// Gets The details for a specific DFS share. 
        /// You can use this to test if a DFS path exists, and see if it has a target that matches a specific one (UncPath)
        /// </summary>
        /// <param name="LinkFullPath"></param>
        /// <param name="UncPath"></param>
        /// <returns>DfsShareDetails</returns>
        public static DfsShareDetails GetDfsShareInfo(string LinkFullPath, string UncPath = null)
        {
            //create our DfsShareStatus struct that we will fill in and return
            DfsShareDetails stat = new DfsShareDetails() { linkExists = false, targetMatch = false, targets = new List<DfsTarget>(), numberOfTargets = 0 };

            //our pointers..
            IntPtr buf = IntPtr.Zero;
            IntPtr pStorage = IntPtr.Zero;

            int ret = NativeMethods.NetDfsGetInfo(LinkFullPath, null, null, 3, out buf);
            if (ret == 0)
            {
                //mark that the given dfs link exists
                stat.linkExists = true;

                //see if the given unc matches a target
                NativeMethods.DFS_INFO_3 info = (NativeMethods.DFS_INFO_3)Marshal.PtrToStructure(buf, typeof(NativeMethods.DFS_INFO_3));
                stat.numberOfTargets = (int)info.NumberOfStorages;

                //if we have targets for this DFS link...
                if (info.NumberOfStorages > 0)
                {
                    //each link can have multilple targets, so loop through them and see if any point to the given UncPath
                    for (int i = 0; i < info.NumberOfStorages; i++)
                    {
                        //assign an object to the pointer of the current target
                        pStorage = new IntPtr(Convert.ToInt64(info.Storage) + i * Marshal.SizeOf(typeof(NativeMethods.DFS_STORAGE_INFO)));
                        NativeMethods.DFS_STORAGE_INFO storage = (NativeMethods.DFS_STORAGE_INFO)Marshal.PtrToStructure(pStorage, typeof(NativeMethods.DFS_STORAGE_INFO));

                        string curLink = String.Format(@"\\{0}\{1}", storage.ServerName, storage.ShareName);

                        //add this link to our DfsShareStatus struct
                        stat.targets.Add(new DfsTarget() { targetPath = curLink, targetStatus = (DFS_TARGET_STATE)storage.State });

                        //see if the target points to the given UNC
                        if (UncPath == curLink)
                            stat.targetMatch = true;
                    }
                }
            }

            //free up our memory
            Marshal.FreeHGlobal(buf);

            return stat;
        }

        /// <summary>
        /// removes an entire dfslink, or a single target from a dfslink.
        /// </summary>
        /// <param name="dfsLinkPath"></param>
        /// <param name="serverName"></param>
        /// <param name="shareName"></param>
        /// <returns>DFSActionStatus</returns>
        public static DFSActionStatus RemoveDFSTarget(string dfsLinkPath, string serverName = null, string shareName = null)
        {
            DFSActionStatus stat;

            int ret = NativeMethods.NetDfsRemove(dfsLinkPath, serverName, shareName);
            if (ret == 0)
                stat = DFSActionStatus.Success;
            else
                stat = DFSActionStatus.Error;


            return stat;
        }

        /// <summary>
        /// adds a dfs link and/or target
        /// </summary>
        /// <param name="dfsLinkPath"></param>
        /// <param name="serverName"></param>
        /// <param name="shareName"></param>
        /// <param name="comment"></param>
        /// <returns>DFSActionStatus</returns>
        public static DFSActionStatus AddDFSTarget(string dfsLinkPath, string serverName, string shareName, string comment = null)
        {
            DFSActionStatus stat;

            int ret = NativeMethods.NetDfsAdd(dfsLinkPath, serverName, shareName, comment, 0);
            if (ret == 0)
                stat = DFSActionStatus.Success;
            else if (ret == 80)
                stat = DFSActionStatus.Error_Duplicate;
            else
                stat = DFSActionStatus.Error;

            return stat;
        }

        #endregion
    }
}
