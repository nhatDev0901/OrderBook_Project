﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OrderBook_Project.Common
{
    [Serializable]
    public class UserLogin
    {
        public string UserID { get; set; }
        public string UserName { get; set; }
        public string Name { get; set; }
        public string GroupID { get; set; }
    }
}