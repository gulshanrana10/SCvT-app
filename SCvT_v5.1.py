"""
Created on Thu May 26 12:22:56 2022

@author: gurana
Email: gulshan.rana@nokia.com
"""

from tkinter import *
from tkinter import filedialog, messagebox
import os
import sys
import dictdiffer as dd
from cryptography.fernet import Fernet
import datetime
import pandas as pd

class Audit(Tk):
    def __init__(self, v):
        Tk.__init__(self)
        self.frame1 = LabelFrame(self, height=8, width=16, labelanchor=N)
        self.frame1.pack(fill=BOTH, side=TOP, padx=15, pady=10)
        l01 = Label(self.frame1, text="Schema and CMCLI validation Tool v{}".format(v), font=("Arial", 16), fg='gray')
        l01.pack(fill=X, padx=10, pady=10)
        self.login_frame = Frame(self, height=8, width=30)
        self.login_frame.pack(fill=BOTH, padx=15, pady=10)
        login_message = Label(self.login_frame, text="Enter the License Key : ", width=20, anchor=E)
        login_message.grid(row=0, column=0, sticky='W', pady=5)
        self.input_key = Entry(self.login_frame, width=30, fg="black")
        self.input_key.grid(row=0, column=1, sticky='W', pady=5)
        login_check = Button(self.login_frame, text="Login", width=5, command=lambda: self.login(self.input_key.get()))
        login_check.grid(row=0, column=2, padx=5, pady=5)
        login_browse = Button(self.login_frame, text="Browse", width=5, command=self.br_lic)
        login_browse.grid(row=0, column=3, padx=5, pady=5)
        self.login_status = Label(self.login_frame, width=40, anchor=E, fg='red')
        self.login_status.grid(row=2, column=0, sticky='W', pady=5, columnspan=3)

    def start_app(self):
        # self.frame1 = LabelFrame(self, height=8, width=16, labelanchor=N)
        # self.frame1.pack(fill=BOTH, side=TOP, padx=15, pady=10)
        self.frame4 = LabelFrame(self, height=4, text="Segregate Data from CMCLI", labelanchor=N, padx=5, pady=8)
        self.frame4.pack(side=TOP, fill=BOTH, padx=15, pady=10)
        self.frame2 = LabelFrame(self, height=10, text="Audit Options", labelanchor=N, padx=5, pady=8)
        self.frame2.pack(side=LEFT, fill=BOTH, padx=15, pady=10)
        self.frame3 = Frame(self, height=10, width=100)
        self.frame3.pack(side=RIGHT, fill=BOTH, padx=15, pady=10)

        # self.widget_frame1()
        self.widget_frame2()
        self.widget_frame3()
        self.widget_frame4()

    def br_lic(self):
        f = filedialog.askopenfilename(parent=self, title="Choose License file",
                                       filetypes=[("License file", "*.key"), ("All files", "*.*")])
        if f:
            o = open(f, 'r').read()
            self.login(o.strip())
        else:
            messagebox.showerror(message="Please select License file or enter the key to login.")

    def login(self, key):
        sec_key = b'_wNC6DD9cCMlaulN7-lUwnhffY-e30RWj6XRAPqzHSg='
        f = Fernet(sec_key)
        # key = self.input_key.get()
        try:
            dec_key = f.decrypt(bytes(key, 'utf-8')).decode('utf-8')
            c_time = datetime.datetime.now()
            t = int(c_time.strftime("%Y%m%d_%H%M%S"))
            try:
                if int(dec_key) >= t:
                    self.login_frame.destroy()
                    self.start_app()
                elif int(dec_key) < t:
                    self.login_status['text'] = "License Expired"
                else:
                    self.login_status['text'] = "Login Failed"
            except:
                self.login_status['text'] = "Login Failed"
        except:
            self.login_status['text'] = "Login Failed"

    # def widget_frame1(self):
    #     l01 = Label(self.frame1, text="Schema and CMCLI validation Tool v2.0", font=("Arial", 16), fg='gray')
    #     l01.pack(fill=X, padx=10, pady=10)

    def widget_frame2(self):
        self.var = IntVar()
        self.ch_var = IntVar()
        r01 = Radiobutton(self.frame2, text='CMCLI', variable=self.var, value=0, command=self.get_option)
        r01.pack(anchor=W)
        r02 = Radiobutton(self.frame2, text='DSA', variable=self.var, value=1, command=self.get_option)
        r02.pack(anchor=W)
        C1 = Checkbutton(self.frame2, text="Write commands", variable=self.ch_var, onvalue=1, offvalue=0, wraplength=80)
        C1.pack()
        self.ch_var.set(0)
        self.var.set(3)

    def widget_frame3(self):
        l02 = Label(self.frame3, text="Option Selected : ", width=14, anchor=E)
        l02.grid(row=0, column=0, sticky='W', pady=5)
        self.l03 = Label(self.frame3, width=24, fg='green')
        self.l03.grid(row=0, column=1, sticky='W', pady=5)
        l04 = Label(self.frame3, text="Reference File : ", width=14, anchor=E)
        l04.grid(row=1, column=0, sticky='W', pady=5)
        l05 = Label(self.frame3, text="Files to compare : ", width=14, anchor=E)
        l05.grid(row=2, column=0, sticky='NW', pady=5)
        self.t01 = Text(self.frame3, width=30, bd=1, height=1, font=("Arial", 8))
        self.t01.grid(row=1, column=1, sticky='W', pady=5)
        self.t02 = Text(self.frame3, width=30, bd=1, height=8, font=("Arial", 8))
        self.t02.grid(row=2, column=1, sticky='W', pady=5)
        self.b01 = Button(self.frame3, text="Start", font=("Arial", 7), width=5,
                          command=self.run, state=DISABLED)
        self.b01.grid(row=0, column=2, padx=5, pady=5)
        self.b02 = Button(self.frame3, text="Browse", font=("Arial", 7), width=5,
                          command=lambda: self.browse_file(c="*.txt", m=False), state=DISABLED)
        self.b02.grid(row=1, column=2, padx=5, pady=5)
        self.b03 = Button(self.frame3, text="Browse", font=("Arial", 7), width=5,
                          command=lambda: self.browse_files(c="*.txt", m=True), state=DISABLED)
        self.b03.grid(row=2, column=2, sticky='NW', padx=5, pady=5)

    def widget_frame4(self):
        b04 = Button(self.frame4, text="Realms", font=("Arial", 7), width=12, command=self.Realm)
        b05 = Button(self.frame4, text="HD Connections", font=("Arial", 7), width=12, command=self.HD)
        b06 = Button(self.frame4, text="LDAP Table", font=("Arial", 7), width=12, command=self.LDAP)
        b04.grid(row=0, column=0, sticky='NW', padx=35, pady=5)
        b05.grid(row=0, column=1, sticky='NW', padx=35, pady=5)
        b06.grid(row=0, column=2, sticky='NW', padx=35, pady=5)

    def browse_file(self, c, m):
        self.ref = filedialog.askopenfilename(parent=self, title="Choose a file", initialdir=os.curdir,
                                              filetypes=(("Template types", c), ("All types", "*")), multiple=m)
        self.t01.delete(1.0, END)
        if self.ref:
            self.t01.configure(fg='black')
            self.t01.insert(1.0, os.path.basename(self.ref))
            self.b03.configure(state=NORMAL)
            if self.fil:
                self.b01.configure(state=NORMAL)
        else:
            self.b01.configure(state=DISABLED)
            self.t01.configure(fg='red')
            self.t01.insert(1.0, "Select reference file")

    def browse_files(self, c, m):
        self.fil = filedialog.askopenfilenames(parent=self, title="Choose a file", initialdir=os.curdir,
                                               filetypes=(("Template types", c), ("All types", "*")), multiple=m)
        self.t02.delete(1.0, END)
        if self.fil:
            for file in self.fil:
                self.t02.configure(fg='black')
                self.t02.insert(END, str(self.fil.index(file) + 1) + ". " + os.path.basename(file) + "\n")
            if self.ref:
                self.b01.configure(state=NORMAL)
            else:
                self.t01.configure(fg='red')
                self.t01.insert(1.0, "Select reference file")
                self.b01.configure(state=DISABLED)
        else:
            self.b01.configure(state=DISABLED)
            self.t02.configure(fg='red')
            self.t02.insert(1.0, "Select files for comparision")

    def browse(self):
        dump_files = filedialog.askopenfilenames(parent=self, title="Choose files", initialdir=os.curdir)
        if dump_files:
            return dump_files
        else:
            messagebox.showerror(message="Files not selected!!! Please try again...")

    def LDAP(self):
        files = self.browse()
        if files:
            for file in files:
                f = os.path.splitext(file)[0] + '_predump.txt'
                r = open(file, 'r')
                w = open(f, 'w')
                for read in r.readlines():
                    if re.search('HostConfigTable', read) or re.search('LDAPAccess.HostConfiguration', read):
                        w.writelines(read)
                r.close()
                w.close()
            messagebox.showinfo(message="Completed...")

    def HD(self):
        files = self.browse()
        if files:
            s = ["Connections[", 'RealmID=HD', 'Realm=hlr', 'InterfaceID=HD', 'Server=hfe', 'System.HdSupportEnabled',
                 'System.HlrRealmForHdInterface',
                 'System.HssRealmForHdInterface', 'System.CancelLocationHdSimCardChangeover',
                 'System.EnableMobilityMgmtOnHdInterface', 'DiameterCommon.DnsPhShortcut']
            for file in files:
                f = os.path.splitext(file)[0] + '_HD.txt'
                r = open(file, 'r')
                w = open(f, 'w')
                for read in r.readlines():
                    if any(i in read for i in s):
                        w.writelines(read)
                r.close()
                w.close()
            messagebox.showinfo(message="Completed...")

    def Realm(self):
        files = self.browse()
        if files:
            for file in files:
                f = os.path.splitext(file)[0] + '_realm.txt'
                r = open(file, 'r')
                w = open(f, 'w')
                word = 'Realms['
                for read in r.readlines():
                    if re.search(word, read):
                        w.writelines(read)
                r.close()
                w.close()
            messagebox.showinfo(message="Completed...")

    def get_option(self):
        self.b01.configure(state=DISABLED)
        self.b02.configure(state=NORMAL)
        self.b03.configure(state=DISABLED)
        self.t01.delete(1.0, END)
        self.t02.delete(1.0, END)
        self.ref = None
        self.fil = None
        # if self.ch_var.get():
        #     w = "with"
        # else:
        #     w = 'without'
        if self.var.get() == 0:
            self.l03['text'] = 'CMCLI Audit'
        elif self.var.get() == 1:
            self.l03['text'] = 'DSA Audit'

    def run(self):
        if self.ref:
            if self.fil:
                if self.var.get() == 0:
                    CmcliAudit(live=self.ref, non_live=self.fil, write_to_file=self.ch_var.get())
                    messagebox.showinfo(message="CMCLI Audit Completed...")
                    self.b01.configure(state=DISABLED)
                elif self.var.get() == 1:
                    DSAAudit(ln=self.ref, nl=self.fil, w=self.ch_var.get())
                    messagebox.showinfo(message="DSA Audit Completed...")
                    self.b01.configure(state=DISABLED)
                self.t01.delete(1.0, END)
                self.t02.delete(1.0, END)
                self.ref = None
                self.fil = None


class CmcliAudit:
    def __init__(self, live, non_live, write_to_file):
        print("\n\nStarting CMCLI Audit")
        print("[INFO]: Reading reference CMCLI from ", live)
        self.reference = self.get_dict(live)
        for f in non_live:
            print("[INFO]: Reading CMCLI from ", f)
            base = os.path.dirname(f)
            d = self.get_dict(f)
            name = os.path.join(base, os.path.basename(f).split('.')[0] + '_diff.txt')
            name1 = os.path.join(base, os.path.basename(f).split('.')[0] + '_diff_actions.txt')
            result = dd.diff(d[0], self.reference[0])
            # Print the differences
            # for i in result:
            #     print(i)
            self.golden_par = self.golden()
            self.du_par, self.cu_par = self.du_specific()
            self.bisp_par = self.bisp_parameters()
            print("[VALUES]: Golden Parameters =>", self.golden_par)
            print("[VALUES]: DU specific Parameters =>", self.du_par)
            print("[VALUES]: Common DU specific Parameters =>", self.cu_par)
            print("[VALUES]: Security Compliance Parameters =>", self.bisp_par)
            if self.golden_par == ['']:
                m1 = messagebox.askokcancel(
                    message='No Golden parameters specified.\nPress OK to continue or CANCEL to exit.')
                if not m1:
                    sys.exit(1)
            if not self.du_par:
                m2 = messagebox.askokcancel(
                    message='No DU specific parameters defined.\nPress OK to continue or CANCEL to exit.')
                if not m2:
                    sys.exit(1)
            if not self.cu_par:
                m3 = messagebox.askokcancel(
                    message='No Common DU specific parameters defined.\nPress OK to continue or CANCEL to exit.')
                if not m3:
                    sys.exit(1)
            if not self.bisp_par:
                m4 = messagebox.askokcancel(
                    message='No BISP specific parameters defined.\nPress OK to continue or CANCEL to exit.')
                if not m4:
                    sys.exit(1)
            cmnd = self.val_diff(dif=result, out=name, dic=d)
            if write_to_file:
                cmd_file = open(name1, 'w+')
                cmd_file.writelines("### CMCLI batch commands\n")
                self.write_cmd(fil=cmd_file, d=cmnd)
                cmd_file.close()

    def get_dict(self, file):
        """
        :param file: Read CMCLI text file.
        :return: CMCLI configurations in dictionary format.
        """
        NUM = {}
        f = open(file, 'r')
        cmcli = {}
        component, table = '  '
        ignore_list = ['Sending Request', 'Authentication Required', 'Please', 'root']
        for line in f.readlines():
            if line.startswith(tuple(ignore_list)):
                print("[INFO]: Line ignored --> ", line.strip())
                pass
            # elif line.startswith("Authentication Required"):
            #     pass
            # elif line.startswith("Please Enter"):
            #     node = line.split('/')[-1][:9]
            elif not line.split():
                pass
            elif line.startswith("COMPONENT="):
                component = line.split('COMPONENT=')[-1].split(':')[0]
                cmcli[component] = {}
                table = ''
            elif line.startswith('#'):
                if line.split(':')[0].find('Table Name') > 0:
                    table = line.split(':')[1].split()[0]
                    cmcli[component][table] = {}
                elif line.split(':')[0].find('Number of Rows') > 0:
                    pass
            else:
                try:
                    a, b = map(lambda x: x.strip(), line.split('=', 1))
                    if b.startswith('-----BEGIN'):
                        # b = b.split('-----')[2]
                        b = '"{0}"'.format(b)
                except IndexError:
                    a, b = line.split('=', 1)[0].strip(), ''
                except ValueError:
                    print("[INFO]: Line ignored --> ", line.strip())
                    continue
                if b in ['true', 'True', 'false', 'False']:
                    b = b.upper()
                if '[' in a:
                    if a.split('[')[0] == table:
                        nu = a.split('[')[1].split(']')[0]
                        NUM['{0}.{1}.{2}={3}'.format(component, table, a.split('.')[-1], b)] = nu
                        try:
                            cmcli[component][table][nu][a.split('.')[-1]] = b
                        except KeyError:
                            cmcli[component][table][nu] = {}
                            cmcli[component][table][nu][a.split('.')[-1]] = b
                    else:
                        cmcli[component][a] = b
                else:
                    cmcli[component][a] = b
        # for i in NUM.keys():
        #     print(i, '->', NUM[i])
        # return cmcli, NUM
        return self.sort_cmcli_dict(cmcli), NUM

    def sort_cmcli_dict(self, d):
        self.name_dic = {'': {'InternalMapping': 'ProcessName'},
               'cmrepo/config': {'CE_Names': 'CE_ID', 'Primary_Parameter': 'Param_NAME', 'server': 'name'},
               'cmrepo/configfiles': {'DependancyTab': 'Source'},
               'cmrepo/files': {'ConfigFileTable': 'FileName', 'LicenceFileTable': 'FileName',
                                'SS7ConfigFileTable': 'FileName'}, 'config/clustercfg': {'server': 'name'},
               'config/icm': {'ICM_CONFIG': 'IcmHostName', 'ICM_CONFIG_OAM': 'IcmHostName'},
               'config/oamcipa': {'CIPA_OAM': 'CIPA_NAME_OAM'},
                'hlri/ach/tplcs': {'GMLCTable': 'GMLCAddress'},
                'hlri/ddh/usd': {'TimeDeviationTable': 'VLRID', 'UssdRespStringTable': 'UssdRespStringKey',
                                 'UssdServiceCodeTable': 'serviceCodeForUssd', 'accessMatrixTable': 'callType',
                                 'funcNumberCfgTable': 'callType'},
                'hlri/hdl': {'HostConfigTable': 'Host'},
               'hlri/ddh/afw/ovld': {'ovldCompCounter': 'UserCounterName', 'CongestTrafficReject': 'ApplicationContext',
                                     'TimerBasedRejTable': 'Operation', 'ovldTrafficReject': 'UserComponentID'},
               'hlri/lte/dia': {'DiaMessageSizeLimit': 'ApplicationName', 'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME',
                                'SctpConfiguration': 'ConnectionID'},
               'hlri/lte/diameterdisp': {'Connections': 'ConnectionID', 'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME',
                                         'CECtxTypes': 'CE', 'Realms': 'RealmID'},
               'hlri/lte/imslb': {'System.DispatcherConfig': 'TLSAliasName', 'System.PrcsAliasMap': 'prcsName',
                                  'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME', 'System.IPAddresses': 'Id',
                                  'System.Ports': 'Direction'},
               'hlri/lte/nem': {'InternalMapping': 'ProcessName'},
               'hlri/ddh/afw': {'HlrdFEAddressTable': 'HLRdFELogicalNode'},
                'hlri/tm/sms': {'srismFrwOriginTable': 'CgPA'},
               'hlri/smi/sysm/syconfdataaccess': {'AllowedgsmSCFTable': 'GsmSCFAddress',
                                                  'EPSFeatureTable': 'featureName', 'NDCTable': 'ndcIndex',
                                                  'QoSPreferenceTable': 'operationType', 'bearerServiceTable': 'bsMapCode',
                                                  'hlrNumberTable': 'beDsaId', 'frTable': 'frMap',
                                                  'natSSDownloadTable': 'ssNationalName', 'ssTable': 'ssMapCode',
                                                  'tcsiSuppTable': 'tcsiName', 'teleServiceTable': 'tsMapCode',
                                                  'bsCombTable': 'bsMap', 'camelAgreementTable': 'catIndex',
                                                  'neFraudCheckTable': 'entitySccpAddress',
                                                  'policedSCCPAddrTable': 'sccpAddress',
                                                  'splShortCodesTable': 'splShortCode', 'tsCombTable': 'tsMap'},
               'hss/sdl': {'SdlAccess.DiscoveryCipherList': 'CipherName', 'SdlAccess.HostConfiguration': 'Host'},
               'ims/common/dia': {'SctpConfiguration': 'ConnectionID'},
               'ims/common/diameterdisp': {'Connections': 'ConnectionID', 'InterfaceIdentities': 'PeerHostName',
                                           'KmgControl.Certificates': 'ParamName', 'AnswerTimers': 'InterfaceID',
                                           'LatencyThres': 'msgType', 'CECtxTypes': 'CE', 'Realms': 'RealmID',
                                           'ResponseTimers': 'InterfaceID', 'SessionIdDispatching': 'ApplicationID'},
               'ims/common/nem': {'InternalMapping': 'ProcessName'},
               'ims/common/imslb': {'System.Ports': 'Direction'},
               'ims/hss/sa/atc': {'ATCAdmFunctAgents': 'Request_ComponentName'},
               'ims/hss/sa/commonconfigdata': {'SMPID.SMPID_Table': 'Value'},
               'ims/hss/tp/acp/actpadapter': {'DomainSqnIndRange': 'authenticationType'},
               'ims/hss/tp/acs/Utimaco-HSM': {'HsmServers': 'name'},
               'ims/hss/tp/overloadhandling': {'Overload.ALBMsgThrottlingRate': 'LoadLevel',
                                               'Overload.DrmpLLMappingTable': 'DrmpVal',
                                               'Overload.LoadThresholdCfg4OutUhhd': 'ServiceOperation',
                                               'Overload.OLRConfiguration': 'LoadLevel',
                                               'Overload.VNFWeightRebalancing': 'AvgResUtilOfAppVMs',
                                               'System.ALBWeightRebalancing': 'AvgResUtilOfALBVMs'},
                'ims/hss/tp/umslb': {'HostConfigTable': 'Host'},
               'ims/hss/tp/umstp': {'KmgControl.Certificates': 'ParamName', 'LDAPAccess.FeDsSet': 'FeDsSetName',
                                    'SdlAccess.DiscoveryCipherList': 'CipherName',
                                    'System.ContextLimit': 'ContextName',
                                    'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME',
                                    'System.IOTFeaturesConfTable': 'ConfigString',
                                    'LDAPAccess.HostConfiguration': 'Host', 'LDAPAccess.LDAPErrorCodes': 'ErrorCode',
                                    'System.GroupProcRateControlTable': 'Message',
                                    'System.SLhServingNodePriority': 'ServingNode'},
               'ngc/ngh2p': {'LoadThresholdConfigTable': 'ServiceOperation'},
               'platform/aom': {'AOM.MeasGranPeriod': 'MeasurementType'},
               'platform/cframe': {'CIPA': 'CIPA_NAME', 'CIPA_NODE_CONFIG': 'CIPA_NAME', 'ENVIRONMENT': 'NAME',
                                   'FRW_LOG4JCATEGORIES': 'TRACETOPICNAME', 'GFHCONFIG': 'CONSINDEX',
                                   'IPSERVICE_ASSIGNMENT': 'LOGICAL_SERVICE_NAME', 'IP_ADDRESS': 'HIP_ADDRESS_NAME',
                                   'IP_ASSIGNMENT': 'LOGICAL_SERVICE_NAME', 'IP_NODE_CONFIG': 'LAN_NAME',
                                   'IP_SERVICE': 'LOGICAL_SERVICE_NAME', 'IP_SERVICE_PORTS': 'LOGICAL_SERVICE_NAME',
                                   'LAN': 'LAN_NAME', 'LAN_ASSIGNMENT': 'LAN_NAME', 'LOGICALDATABASES': 'LOGICALDBNAME',
                                   'LOGICALDIRECTORIES': 'LOGICALNAME', 'SECURITY_MODE': 'EXT_SECURITY_PROPERTY_NAME',
                                   'SSL_EXTENDED_OPTIONS': 'EXT_SECURITY_PROPERTY_NAME',
                                   'STARTUP_GROUP': 'STARTUP_GROUP_NAME', 'STARTUP_GROUP_ASSIGN': 'PROCESSGROUP_NAME',
                                   'TRUSTED_COMPONENTS': 'COMPNAME', 'SECURITY_PROPERTIES': 'SECURITY_PROPERTY_NAME',
                                   'EXCLUDEDPKGPATHS': 'PKGPATH', 'FILTERPATHS': 'PREFIX',
                                   'IP_CLUSTER_ROUTING': 'DESTINATION', 'IP_DYNAMIC_ROUTING': 'DESTINATION',
                                   'SSL_TRUSTED_CALIST': 'EXT_SECURITY_PROPERTY_NAME',
                                   'TidConfigTable': 'TidPrefix'},
               'platform/dbconfig': {'DBCFGMAPPINGTABLE': 'CFRAMENAME'},
               'platform/filewriter': {'MFWTypeDescription': 'MFWTypeName_Version'},
               'platform/httpcl': {'HttpClServers': 'serverName', 'HttpClServices': 'serviceName'},
               'platform/httpsv': {'HttpSvServices': 'serviceName', 'HttpSvWhiteList': 'clientIpAddress'},
               'platform/keymanagement': {'Components': 'UsecaseName', 'KeyAudit': 'UseCaseName',
                                          'KeySubTypes': 'KeySubTypeName', 'KeysetTypeIds': 'KeysetTypeName',
                                          'KeysetTypes': 'KeysetTypeName', 'Usecases': 'UsecaseName',
                                          'RsaPublicKeyList': 'UseCaseName'},
               'platform/logging': {'Log_Types': 'Name'},
               'platform/oam/omfmagent': {'AlarmFilter.Rules': 'UniqueRuleName'},
               'platform/rtpconfig': {'RTPCFGMAPPINGTABLE': 'CFRAMENAME', 'CUSTREACTORS': 'KEY',
                                      'CUSTSTARTUPDEPSTABLE': 'KEY'},
               'platform/security': {'RBAC': 'ROLE_NAME'},
                         'platform/trafficcontrol': {'PLFTLM_LIMITOBJECTS': 'Identifier'},
                         'platform/tsp/Common': {'ConditionalSuppression': 'Severity'}}

        # dic = d
        for k in self.name_dic.keys():
            for k1 in self.name_dic[k].keys():
                try:
                    d[k][k1] = dict(sorted(d[k][k1].items(), key=lambda x: int(x[1][self.name_dic[k][k1]])))
                except ValueError:
                    # print(e)
                    d[k][k1] = dict(sorted(d[k][k1].items(), key=lambda x: x[1][self.name_dic[k][k1]]))
                except KeyError as ee:
                    print("[INFO]: Key not found in dictionary ", ee)
                    pass
        return d

    def val_diff(self, dif, out, dic):
        c, t, a, n1 = '    '
        ex = {'BISP': [], 'DU': [], 'CommonDU': [], 'Other': []}
        o = open(out, 'w+')
        o.writelines("CMCLI differences\n")
        extra = []
        for line in dif:
            oper = line[0]
            if type(line[1]) == str:
                if len(line[1].split('.')) == 2:
                    c, a = line[1].split('.')
                    t, n1 = '#', '#'
                elif len(line[1].split('.')) == 4:
                    c, t, n1, a = line[1].split('.')
                elif len(line[1].split('.')) == 3:
                    # print('line-->', line)
                    c, t, n1 = line[1].split('.')
                    self.extra_value(dd=dic, ope=oper, c=c, t=t, n=n1, dic=ex, v=line[2], o=o)
                    continue
            elif type(line[1]) == list:
                if len(line[1]) == 2:
                    # print(line)
                    c, a = line[1]
                    t, n1 = '#', '#'
                    # print(c, a, t)
                elif len(line[1]) == 4:
                    c, t, n1, a = line[1]
                elif len(line[1]) == 3:
                    c, t, n1 = line[1]
                    self.extra_value(dd=dic, ope=oper, c=c, t=t, n=n1, dic=ex, v=line[2], o=o)
                    continue
            if not (a in self.golden_par or t in self.golden_par):
                s = []
                nnn = {'': {'InternalMapping': 'ProcessName'},
                       'cmrepo/config': {'CE_Names': 'CE_ID', 'Primary_Parameter': 'Param_NAME',
                                         'server': 'name'},
                       'cmrepo/configfiles': {'DependancyTab': 'Source'},
                       'cmrepo/files': {'ConfigFileTable': 'FileName', 'LicenceFileTable': 'FileName',
                                        'SS7ConfigFileTable': 'FileName'},
                       'config/clustercfg': {'server': 'name'},
                       'config/icm': {'ICM_CONFIG': 'IcmHostName', 'ICM_CONFIG_OAM': 'IcmHostName'},
                       'config/oamcipa': {'CIPA_OAM': 'CIPA_NAME_OAM'},
                       'hlri/ddh/afw/ovld': {'ovldCompCounter': 'UserCounterName'},
                       'hlri/lte/dia': {'DiaMessageSizeLimit': 'ApplicationName',
                                        'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME'},
                       'hlri/lte/diameterdisp': {'Connections': 'LogicalName',
                                                 'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME'},
                       'hlri/lte/imslb': {'System.DispatcherConfig': 'TLSAliasName',
                                          'System.PrcsAliasMap': 'prcsName',
                                          'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME'},
                       'hlri/lte/nem': {'InternalMapping': 'ProcessName'},
                       'platform/aom': {'AOM.MeasGranPeriod': 'MeasurementType'},
                       'hlri/smi/sysm/syconfdataaccess': {'AllowedgsmSCFTable': 'GsmSCFAddress',
                                                          'EPSFeatureTable': 'featureName',
                                                          'NDCTable': 'ndcIndex',
                                                          'QoSPreferenceTable': 'operationType',
                                                          'bearerServiceTable': 'bsName',
                                                          'hlrNumberTable': 'beDsaHostName',
                                                          'natSSDownloadTable': 'ssNationalName',
                                                          'ssTable': 'ssName', 'tcsiSuppTable': 'tcsiName',
                                                          'teleServiceTable': 'tsName'},
                       'hss/sdl': {'SdlAccess.DiscoveryCipherList': 'CipherName'},
                       'ims/common/diameterdisp': {'Connections': 'LogicalName',
                                                   'InterfaceIdentities': 'PeerHostName',
                                                   'KmgControl.Certificates': 'ParamName'},
                       'ims/common/nem': {'InternalMapping': 'ProcessName'},
                       'ims/hss/sa/atc': {'ATCAdmFunctAgents': 'Request_ComponentName'},
                       'ims/hss/tp/acs/Utimaco-HSM': {'HsmServers': 'name'},
                       'ims/hss/tp/umstp': {'KmgControl.Certificates': 'ParamName',
                                            'LDAPAccess.FeDsSet': 'FeDsSetName',
                                            'SdlAccess.DiscoveryCipherList': 'CipherName',
                                            'System.ContextLimit': 'ContextName',
                                            'TSP.RTPCFGMAPPINGTABLE': 'CFRAMENAME'},
                       'platform/cframe': {'CIPA': 'CIPA_NAME', 'CIPA_NODE_CONFIG': 'CIPA_NAME',
                                           'ENVIRONMENT': 'NAME', 'FRW_LOG4JCATEGORIES': 'TRACETOPICNAME',
                                           'GFHCONFIG': 'COUNTERNAME',
                                           'IPSERVICE_ASSIGNMENT': 'LOGICAL_SERVICE_NAME',
                                           'IP_ADDRESS': 'HIP_ADDRESS_NAME',
                                           'IP_ASSIGNMENT': 'LOGICAL_SERVICE_NAME',
                                           'IP_NODE_CONFIG': 'LAN_NAME',
                                           'IP_SERVICE': 'LOGICAL_SERVICE_NAME',
                                           'IP_SERVICE_PORTS': 'LOGICAL_SERVICE_NAME', 'LAN': 'LAN_NAME',
                                           'LAN_ASSIGNMENT': 'LAN_NAME',
                                           'LOGICALDATABASES': 'LOGICALDBNAME',
                                           'LOGICALDIRECTORIES': 'LOGICALNAME',
                                           'SECURITY_MODE': 'EXT_SECURITY_PROPERTY_NAME',
                                           'SSL_EXTENDED_OPTIONS': 'EXT_SECURITY_PROPERTY_NAME',
                                           'STARTUP_GROUP': 'STARTUP_GROUP_NAME',
                                           'STARTUP_GROUP_ASSIGN': 'PROCESSGROUP_NAME',
                                           'TRUSTED_COMPONENTS': 'COMPNAME'},
                       'platform/dbconfig': {'DBCFGMAPPINGTABLE': 'CFRAMENAME'},
                       'platform/filewriter': {'MFWTypeDescription': 'MFWTypeName_Version'},
                       'platform/httpcl': {'HttpClServers': 'serverName', 'HttpClServices': 'serviceName'},
                       'platform/httpsv': {'HttpSvServices': 'serviceName',
                                           'HttpSvWhiteList': 'clientName'},
                       'platform/keymanagement': {'Components': 'UsecaseName', 'KeyAudit': 'UseCaseName',
                                                  'KeySubTypes': 'KeySubTypeName',
                                                  'KeysetTypeIds': 'KeysetTypeName',
                                                  'KeysetTypes': 'KeysetTypeName',
                                                  'Usecases': 'UsecaseName'},
                       'platform/logging': {'Log_Types': 'Name'},
                       'platform/oam/omfmagent': {'AlarmFilter.Rules': 'UniqueRuleName'},
                       'platform/rtpconfig': {'RTPCFGMAPPINGTABLE': 'CFRAMENAME'},
                       'platform/security': {'RBAC': 'ROLE_NAME'},
                       'hlri/ddh/afw': {'HlrdFEAddressTable': 'HLRdFELogicalNode'}}
                ccc = False
                if oper == 'change':
                    try:
                        v = dic[0][c][t][n1]
                        # nn10 = '{0}.{1}.{2}={3}'.format(c, t, a, line[2][0])
                        nn11 = '{0}.{1}.{2}={3}'.format(c, t, a, line[2][1])
                        # ch3 = False
                        try:
                            non = nnn[c][t]
                            cc = self.check_change(c=c, t=t, non=non, v=v, extra=extra, n1=n1, dic=dic)
                            if cc:
                                continue

                        except KeyError:
                            if v in self.reference[0][c][t].values():
                                if nn11 not in dic[1].keys():
                                    # print("INS 1", self.reference[0][c][t][n1])
                                    e = {'ope': 'add', 'c': c, 't': t, 'a': t, 'num': '##',
                                         'val': [(n1, self.reference[0][c][t][n1])], 'd': ''}
                                    extra.append(e)
                                continue
                            else:
                                if nn11 in dic[1].keys():
                                    # print("DEL 3", v)
                                    e = {'ope': 'remove', 'c': c, 't': t, 'a': t, 'num': '##', 'val': [(n1, v)], 'd': ''}
                                    extra.append(e)
                                    continue
                        for k in v.keys():
                            s.append("{0}={1}".format(k, v[k]))
                    except KeyError as e:
                        if e != '#':
                            print("[INFO]: Ignored ", e)
                        pass
                elif oper == 'add':
                    # code for excluding NodeType form the keys
                    al = []
                    if line[1] == '':
                        for va in line[2]:
                            for (vak, vav) in va[1].items():
                                if type(vav) == dict:
                                    dc = [(x, y) for (x, y) in vav.items()]
                                    aa = vak
                                    # self.read_diff(op=oper, c=va[0], t=vak, a=vak, num='##', val=dc, o=o, d=s, dic=ex)
                                else:
                                    dc = [('1', {vak: vav})]
                                    aa = ''
                                self.read_diff(op=oper, c=va[0], t=vak, a=aa, num='##', val=dc, o=o, d=s, dic=ex)
                        continue
                    elif type(line[1]) == str and '.' not in line[1]:
                        # print('new-->', line)
                        for ii in line[2]:
                            if type(ii[1]) == dict:
                                dc = [(x, y) for (x, y) in ii[1].items()]
                                aa = ii[0]
                                # self.read_diff(op=oper, c=line[1], t=ii[0], a=ii[0], num='##', val=dc, o=o, d=s, dic=ex)
                            else:
                                dc = [('1', {ii[0]: ii[1]})]
                                aa = ''
                            self.read_diff(op=oper, c=line[1], t=ii[0], a=aa, num='##', val=dc, o=o, d=s, dic=ex)
                        continue
                    else:
                        for itr in line[2]:
                            # print(itr)
                            ccc = False
                            try:
                                kk = self.name_dic[c][a]
                                # self.reference[0][c][t][n1][non]
                                kk1 = '{0}.{1}.{2}={3}'.format(c, a, kk, self.reference[0][c][a][itr[0]][kk])
                                # print(kk1)
                                if itr[1] in dic[0][c][a].values():
                                    # print('NO add-->', itr)
                                    al.append(itr)
                                elif kk1 in dic[1].keys():
                                    itr2 = dic[0][c][a][dic[1][kk1]]
                                    com = itr2.items() ^ itr[1].items()
                                    if com:
                                        if len(com) == 2 and ['NodeType' in x for x in com] == [True, True]:
                                            # print('NO add2', kk1)
                                            pass
                                        else:
                                            res = dd.diff(itr2, itr[1])
                                            ss = []
                                            for k in itr2.keys():
                                                ss.append("{0}={1}".format(k, itr2[k]))
                                            for rr in res:
                                                if not rr[1] == 'NodeType':
                                                    e = {'ope': rr[0], 'c': c, 't': a, 'a': rr[1], 'num': '##',
                                                         'val': rr[2],
                                                         'd': ss}
                                                    extra.append(e)
                                            # print('ModifyX1-->', kk1, com)
                                        al.append(itr)
                                        # line[2].pop(line[2].index(itr))
                                        # ccc = True
                            except:
                                print('To be check manually : Operation = Add ', itr, "\n", line)

                    for x in al:
                        line[2].pop(line[2].index(x))

                elif oper == 'remove':
                    rl = []
                    if line[1] == '':
                        # print('under-->', line)
                        for va in line[2]:
                            for (vak, vav) in va[1].items():
                                if type(vav) == dict:
                                    dc = [(x, y) for (x, y) in vav.items()]
                                    aa = vak
                                    # self.read_diff(op=oper, c=va[0], t=vak, a=vak, num='##', val=dc, o=o, d=s, dic=ex)
                                else:
                                    dc = [('1', {vak: vav})]
                                    aa = ''
                                self.read_diff(op=oper, c=va[0], t=vak, a=aa, num='##', val=dc, o=o, d=s, dic=ex)
                        continue
                    elif type(line[1]) == str and '.' not in line[1]:
                        # print('new-->', line)
                        for ii in line[2]:
                            if type(ii[1]) == dict:
                                dc = [(x, y) for (x, y) in ii[1].items()]
                                aa = ii[0]
                                # self.read_diff(op=oper, c=line[1], t=ii[0], a=ii[0], num='##', val=dc, o=o, d=s, dic=ex)
                            else:
                                dc = [('1', {ii[0]: ii[1]})]
                                aa = ''
                            self.read_diff(op=oper, c=line[1], t=ii[0], a=aa, num='##', val=dc, o=o, d=s, dic=ex)
                        continue
                    else:
                        for itr in line[2]:
                            ccc = False
                            try:
                                kk = self.name_dic[c][a]
                                # self.reference[0][c][t][n1][non]
                                kk1 = '{0}.{1}.{2}={3}'.format(c, a, kk, dic[0][c][a][itr[0]][kk])
                                if itr[1] in self.reference[0][c][a].values():
                                    rl.append(itr)
                                    # print('NO remove-->', itr)
                                    # ccc = True
                                elif kk1 in self.reference[1].keys():
                                    itr2 = self.reference[0][c][a][self.reference[1][kk1]]
                                    com = itr2.items() ^ itr[1].items()
                                    if com:
                                        if len(com) == 2 and ['NodeType' in x for x in com] == [True, True]:
                                            # print('No remove2', kk1)
                                            pass
                                            # continue
                                        else:
                                            res = dd.diff(itr[1], itr2)
                                            ss = []
                                            for k in itr[1].keys():
                                                ss.append("{0}={1}".format(k, itr[1][k]))
                                            for rr in res:
                                                if not rr[1] == 'NodeType':
                                                    e = {'ope': rr[0], 'c': c, 't': a, 'a': rr[1], 'num': '##',
                                                         'val': rr[2],
                                                         'd': ss}
                                                    extra.append(e)
                                            # print('ModifyX2-->', kk1, com)
                                        rl.append(itr)
                                        # line[2].pop(line[2].index(itr))
                                        # ccc = True
                            except KeyError:
                                print('To be check manually : Operation = Remove ', itr, "\n", line)

                    for x in rl:
                        line[2].pop(line[2].index(x))

                if not ccc:
                    self.read_diff(op=oper, c=c, t=t, a=a, num=n1, val=line[2], o=o, d=s, dic=ex)
        # print('extra -->', extra)
        aa = []
        for l in extra:
            if l not in aa:
                aa.append(l)
        for l in aa:
            # print('new mod-->', l)
            self.read_diff(op=l['ope'], c=l['c'], t=l['t'], a=l['a'], num=l['num'], val=l['val'], o=o, d=l['d'], dic=ex)
        o.close()
        return ex

    def check_change(self, c, t, non, v, extra, n1, dic):
        cc = False
        nn20 = '{0}.{1}.{2}={3}'.format(c, t, non, v[non])
        nn21 = '{0}.{1}.{2}={3}'.format(c, t, non, self.reference[0][c][t][n1][non])
        if nn20 == nn21:
            # if
            com = v.items() ^ self.reference[0][c][t][n1].items()
            if com:
                if len(com) == 2 and ['NodeType' in x for x in com] == [True, True]:
                    # print("No MOD", nn20)
                    return True
            else:
                return True
        else:
            if nn20 in self.reference[1].keys():
                com = v.items() ^ self.reference[0][c][t][self.reference[1][nn20]].items()
                if com:
                    if len(com) == 2 and ['NodeType' in x for x in com] == [True, True]:
                        # print("No mod", nn20)
                        pass
                    else:
                        res = dd.diff(v, self.reference[0][c][t][self.reference[1][nn20]])
                        ss = []
                        for k in v.keys():
                            ss.append("{0}={1}".format(k, v[k]))
                        for rr in res:
                            if not rr[1] == 'NodeType':
                                e = {'ope': rr[0], 'c': c, 't': t, 'a': rr[1], 'num': '##', 'val': rr[2],
                                     'd': ss}
                                extra.append(e)
                cc = True
            else:
                # print("DEL 0-->", nn20, v)
                e = {'ope': 'remove', 'c': c, 't': t, 'a': t, 'num': '##', 'val': [(n1, v)], 'd': ''}
                extra.append(e)
                cc = True

            if nn21 in dic[1].keys():
                com1 = dic[0][c][t][dic[1][nn21]].items() ^ self.reference[0][c][t][
                    self.reference[1][nn21]].items()
                if com1:
                    if len(com1) == 2 and ['NodeType' in x for x in com1] == [True, True]:
                        # print("No mod", nn21)
                        pass
                    else:
                        res1 = dd.diff(dic[0][c][t][dic[1][nn21]],
                                       self.reference[0][c][t][self.reference[1][nn21]])
                        ss = []
                        for k in dic[0][c][t][dic[1][nn21]].keys():
                            ss.append("{0}={1}".format(k, dic[0][c][t][dic[1][nn21]][k]))
                        for rr in res1:
                            if not rr[1] == 'NodeType':
                                e = {'ope': rr[0], 'c': c, 't': t, 'a': rr[1], 'num': '##', 'val': rr[2],
                                             'd': ss}
                                extra.append(e)
                        # print('compareA-->', nn21, com1, [res1])
                cc = True
                # print("compare nn1 from live and non live", nn1)
            else:
                # print("INS 0-->", nn21, self.reference[0][c][t][self.reference[1][nn21]])
                e = {'ope': 'add', 'c': c, 't': t, 'a': t, 'num': '##', 'val': [(n1, self.reference[0][c][t][self.reference[1][nn21]])],
                     'd': ''}
                extra.append(e)
                cc = True
        return cc

    def golden(self):
        gp = ['']
        try:
            g = open('Golden_Parameters.txt', 'r')
            for l in g.readlines():
                if not l.startswith('#'):
                    if l.strip():
                        gp.append(l.strip())
            g.close()
        except FileNotFoundError:
            messagebox.showerror(message="Golden_Parameters.txt not found in current directory.")
            sys.exit(1)
        # print("VALUES : Golden Parameters =>", [x for x in gp])
        return gp

    def du_specific(self):
        du = []
        cdu = []
        try:
            o = open('DU_specific.txt', 'r')
            for r in o.readlines():
                if not r.startswith('#'):
                    if r.strip():
                        if r.startswith('DU='):
                            du = [x.strip() for x in r[3:].split(',')]
                        elif r.startswith('CommonDU='):
                            cdu = [x.strip() for x in r[9:].split(',')]
            o.close()
        except FileNotFoundError:
            messagebox.showerror(message="DU_specific.txt not found in current directory.")
            sys.exit(1)
        # print("VALUES : DU specific Parameters =>", [x for x in du])
        # print("VALUES : Common DU specific Parameters =>", [x for x in cdu])
        return du, cdu

    def bisp_parameters(self):
        bisp = {'arg': []}
        try:
            o = open('Security_Compliance_Parameters.txt', 'r')
            for r in o.readlines():
                if r.strip() and not r.startswith('#'):
                    try:
                        c, a, v = r.strip().split(';')
                        bisp['arg'].append(a)
                        if c not in bisp.keys():
                            bisp[c] = {}
                        bisp[c][a] = v
                    except ValueError:
                        messagebox.showerror(message="Error in below line in Security_Compliance_Parameters.txt file."
                                                     "\n{0}".format(r))
            o.close()
        except FileNotFoundError:
            messagebox.showerror(message="Security_Compliance_Parameters.txt not found in current directory.")
            sys.exit(1)
        # print("VALUES : Security Compliance Parameters =>", [x for x in bisp])
        return bisp

    def write_cmd(self, fil, d):
        for k in d.keys():
            fil.writelines("\n\n###{0} parameters specific changes\n\n".format(k))
            for c in d[k]:
                fil.writelines(c)

    def check_par(self, a):
        if a in self.du_par:
            return 'DU'
        elif a in self.cu_par:
            return 'CommonDU'
        else:
            # for k in self.bisp_par.keys():
            #     if a in self.bisp_par[k].keys():
            #         return 'BISP'
            return 'Other'

    def extra_value(self, dd, c, t, n, v, o, dic, ope):
        d1 = self.reference[0][c][t][n]
        d2 = dd[0][c][t][n]
        e = ' '.join(['{0}={1}'.format(x, d1[x]) for x in d1])
        f = ' '.join(['{0}={1}'.format(y[0], y[1]) for y in v])
        g = ' '.join(['{0}={1}'.format(x, d2[x]) for x in d2])
        if ope == 'add':
            o.writelines("\n############# ADD NEW VALUE IN TABLE")
            dic[self.check_par(a=t)].append("MOD {0} {1} '{2} {3}' --where '{2}'\n".format(c, t, g, f))
        elif ope == 'remove':
            o.writelines("\n############# REMOVE EXTRA VALUE FROM TABLE")
            dic[self.check_par(a=t)].append("MOD {0} {1} '{2}' --where '{3}'\n".format(c, t, e, g))
        o.writelines(["\nComponent   : ", c])
        o.writelines(["\nTable Name  : ", t, "\n"])
        o.writelines(["Table Data  : ", ", ".join(g.split(' ')), "\n"])
        for z in v:
            o.writelines(["\nAttribute   : ", z[0], "\n"])
            o.writelines(["Value       : ", z[1], "\n"])
        o.writelines(["\n"])

    def read_diff(self, op, c, t, a, num, val, o, d, dic):
        s = " ".join(d)
        table = False
        if op == "change":
            if val[0].upper() != val[1].upper():
                if num not in ['', '#']:
                    table = True
                    dic[self.check_par(a=t)].append("MOD {0} {1} '{2}={3}' --where '{4}'\n".format(c, t, a, val[1], s))
                else:
                    pref = ''
                    if ' ' in val[1]:
                        if not val[1][0] == '"':
                            pref = '"'
                    if a in self.bisp_par['arg'] and c in self.bisp_par.keys():
                        c_val = self.bisp_par[c][a]
                        if val[0] != c_val:
                            dic['BISP'].append("setval {0} {1}={3}{2}{3}\n".format(c, a, c_val, pref))
                        else:
                            return
                    else:
                        dic[self.check_par(a=a)].append("setval {0} {1}={3}{2}{3}\n".format(c, a, val[1], pref))
                o.writelines("\n############# MODIFICATION")
                o.writelines(["\nComponent   : ", c])
                if table:
                    o.writelines(["\nTable Name  : ", t])
                    o.writelines(["\nTable Data  : ", ", ".join(s.split(' '))])
                o.writelines(["\nAttribute   : ", a])
                o.writelines(["\nChange From : ", val[0], "\nChange To   : ", val[1]])
                o.writelines("\n")

        elif op == "add":
            # print('d-->', d)
            # print('val>', val)
            o.writelines("\n############# ADDITION")
            o.writelines(["\nComponent   : ", c])
            if a:
                o.writelines(["\nTable Name  : ", a, "\n"])
            second = False
            s2 = []
            for l in val:
                s1 = []
                try:
                    for k in l[1].keys():
                        o.writelines(["\n", k, " : ", l[1][k]])
                        if l[1][k]:
                            s1.append("{0}={1}".format(k, l[1][k]))
                        else:
                            s1.append("{0}= ".format(k))
                    dic[self.check_par(a=a)].append("INS {0} {1} '{2}'\n".format(c, a, " ".join(s1)))
                    o.writelines("\n")
                except KeyError:
                    if type(l[1]) == dict:
                        dc = [(x, y) for (x, y) in l[1].items()]
                        arg = l[0]
                        # self.read_diff(op='add', c=c, t=l[0], a=l[0], num='##', val=dc, o=o, d=s, dic=dic)
                    else:
                        dc = [('1', {l[0]: l[1]})]
                        arg = ''
                    self.read_diff(op='add', c=c, t=l[0], a=arg, num='##', val=dc, o=o, d=s, dic=dic)
                    o.writelines("\n")
                except AttributeError:
                    if not second:
                        o.writelines(["\nTable Name  : ", t, "\n"])
                    o.writelines(["\n", l[0], " : ", l[1]])
                    s2.append("{0}={1}".format(l[0], l[1]))
                    second = True
                    # o.writelines("\n")
            if second:
                dic[self.check_par(a=t)].append("MOD {0} {1} '{3} {2}' --where '{3}'\n".format(c, t, " ".join(s2),
                                                " ".join(d)))
                o.writelines("\n")

        elif op == "remove":
            o.writelines("\n############# REMOVAL")
            o.writelines(["\nComponent   : ", c])
            if a:
                o.writelines(["\nTable Name  : ", a, "\n"])
            for l in val:
                s1 = []
                try:
                    for k in l[1].keys():
                        cc = False
                        # print(k, l[1][k])
                        if type(l[1][k]) == dict:
                            o.writelines(["\nTable Name  : ", k, "\n"])
                            for k1 in l[1][k].keys():
                                for k2 in l[1][k][k1].keys():
                                    o.writelines(["\n", k2, " : ", l[1][k][k1][k2]])
                                    if l[1][k][k1][k2]:
                                        s1.append("{0}={1}".format(k2, l[1][k][k1][k2]))
                                    else:
                                        s1.append("{0}= ".format(k2))
                            dic[self.check_par(a=a)].append("DEL {0} {1} --where '{2}'\n".format(c, a, " ".join(s1)))
                            cc = True
                        else:
                            o.writelines(["\n", k, " : ", l[1][k]])
                            if l[1][k]:
                                s1.append("{0}={1}".format(k, l[1][k]))
                            else:
                                s1.append("{0}= ".format(k))
                    o.writelines("\n")
                    if not cc:
                        dic[self.check_par(a=a)].append("DEL {0} {1} --where '{2}'\n".format(c, a, " ".join(s1)))
                except AttributeError as e:
                    dic[self.check_par(a=a)].append("DEL {0} --where '{1}={2}'\n".format(c, l[0], l[1]))
            # o.writelines("\n")


class DSAAudit:
    def __init__(self, ln, nl, w):
        self.get_difference(live=ln, non_live=nl, write=w)

    def read_dsa(self, file, write_to_file):
        rf = open(file, 'r')
        dsa = {}
        key = '0'
        dsa[key] = {}
        ignore_line = ['rds', 'bds', 'root', 'search:', 'result:']
        for l in rf.readlines():
            if not l.startswith("#"):
                p = l.split(": ", 1)
                if p[0] == 'dn':
                    s = p[1].split("dsaId=")
                    key = s[0].strip()
                    if key in dsa.keys():
                        print("[INFO]: Dual definition of DN ", key)
                    dsa[key] = {}
                    dsa['def'] = s[1].strip()
                elif l == '\n':
                    pass
                elif l.startswith(tuple(ignore_line)):
                    pass
                else:
                    q = l.split(":", 1)
                    s = q[1].strip()                
                    if q[0] in dsa[key].keys():     
                        if type(dsa[key][q[0]]) == list:
                            dsa[key][q[0]].append(s)
                        elif type(dsa[key][q[0]]) == str:
                            tmp = dsa[key][q[0]]
                            dsa[key][q[0]] = [tmp]
                            dsa[key][q[0]].append(s)
                    else:
                        dsa[key][q[0]] = s
        if write_to_file:
            fw = os.path.join(os.path.dirname(file), os.path.basename(file).split('.')[0] + '_dsa_triggers_only.txt')
            wf = open(fw, 'w+')
            fw1 = os.path.join(os.path.dirname(file), os.path.basename(file).split('.')[0] + '_dsa_info.txt')
            wf1 = open(fw1, 'w+')
            for k in sorted(dsa.keys()):
                # For full comparision with values
                wf1.writelines([k, " : ", str(dsa[k]), "\n"])
                # For only trigger name comparision
                wf.writelines([k, " : ", "\n"])
            wf.close()
            wf1.close()

        rf.close()
        return dsa

    def add_value_ldif(self, o, dn, dsaid, arg, val, ope,d):
        o.writelines("dn: {0}dsaId={1}\n".format(dn, dsaid))
        o.writelines("changetype: modify\n")
        o.writelines("{0}: {1}\n".format(ope, arg))
        o.writelines("{0}: {1}\n\n".format(arg, val))
        op = 'ADD VALUES TO DN'
        temp=("Operation : {0}{1}DN    : {2}dsaId={3}\n").format(op, ' ' * (50 - len(op)), dn,dsaid)
        d.writelines(temp)
        temp=("Attribute : {0}{1}Value : {2}\n\n").format(arg, ' ' * (50 - len(arg)), val)                                                                                                                            
        d.writelines(temp)
    def cmd_format(self, dic, o,d):
        for k in dic.keys():
            if k == 'def':
                pass
            elif type(dic[k]) == str:
                o.writelines("{0}: {1}\n".format(k, dic[k]))
                temp=(" Attribute: {0}{1}Value: {2}\n").format(k," "*(50-len(k)),dic[k])
                d.writelines(temp)
            elif type(dic[k]) == list:
                for v in dic[k]:
                    # print(d[k])
                    o.writelines("{0}: {1}\n".format(k, v))
                    temp=(" Attribute: {0}{1}Value: {2}\n").format(k," "*(50-len(k)),v)
                    d.writelines(temp)
        d.writelines("\n")            
        o.writelines("\n")

    def remove_value_ldif(self, o, dn, dsaid, arg,val,d):
        o.writelines("dn: {0}dsaId={1}\n".format(dn, dsaid))
        o.writelines("changetype: modify\n")
        o.writelines("delete: {0}\n".format(arg))
        o.writelines("{0}: {1}\n\n".format(arg, val))
        temp=("Attribute : {0}{1}Value : {2}\n".format(arg, ' ' * (50 - len(arg)), val))
        d.writelines(temp)                                                                                                                            
        
    def validate_diff(self, d, dsa_dict, name, dsaId, write_cmnd):
        diff_out= open(name + "_diff.txt", 'w')
        if write_cmnd:
            out = open(name + "_diff_actions.txt", 'w')

        for i in sorted(d, key=lambda x: x[0]):
            
            if i[0] == 'add':            
                if i[1] == '':    
                    op = 'ADD DN'
                    for j in i[2]:                       
                        dsa_dict[j[0]] = {}                     
                        for ij in j[1].keys():
                            dsa_dict[j[0]][ij] = j[1][ij]
                            if ij == 'def': continue                         
                        # Print ldif format for new DN addition
                        if write_cmnd:                                    
                            out.writelines("dn: {0}dsaId={1}\n".format(j[0], dsaId))
                            temp=("Operation : {0}{1}DN    : {2}dsaId={3}\n").format(op, ' ' * (50 - len(op)), j[0], dsaId)
                            diff_out.writelines(temp)
                            self.cmd_format(dic=j[1], o=out,d=diff_out)

                else:
                    # of.writelines("###Below are extra values to be added in below DN in non-live DSA\n")                 
                    try:
                        dn, arg = i[1].split(".")
                        
                        for k in i[2]:
                            if not k[1] in dsa_dict[dn][arg]:                              
                                dsa_dict[dn][arg].append(k[1])
                                if write_cmnd:                                    
                                    self.add_value_ldif(o=out, ope='add', dn=dn, dsaid=dsaId, arg=arg, val=k[1],d=diff_out)
                            else:
                                # of.writelines('Value : "{0}" already defined in "{1}.{2}"\n'.format(k[1], dn, arg))
                                continue
                    except:
                        if type(i[1]) == list:
                            dn = i[1][0]                            
                        else:
                            dn = i[1]                            
                            #arg=i[1][1]
                        for kk in i[2]:
                            if type(i[1]) == list:
                                args=i[1][1]
                            else:
                                args=kk[0]                            
                            dsa_dict[dn][kk[0]] = args                          
                            if write_cmnd:
                                self.add_value_ldif(o=out, ope='add', dn=dn, dsaid=dsaId, arg=args, val=kk[1],d=diff_out)

            elif i[0] == 'change':
               
                if i[1] == 'def':
                    continue
              
                try:
                    dn, arg = i[1].split(".")
                    dsa_dict[dn][arg] = i[2][1]
                    if write_cmnd:
                        self.add_value_ldif(o=out, ope='replace', dn=dn, dsaid=dsaId, arg=arg, val=i[2][1],d=diff_out)

                except AttributeError:
                    dn, arg = i[1][0], i[1][1]
                    if i[2][1] in dsa_dict[dn][arg]:
                        # of.writelines('Value : "{0}" already defined in "{1}.{2}".\n'.format(i[2][1], dn, arg))
                        continue
                    else:
                        try:
                            dsa_dict[dn][arg].append(i[2][1])
                            if write_cmnd:
                                if arg == 'soapUrlList' or arg == 'optAttrIds':
                                    
                                    self.add_value_ldif(o=out, ope='add', dn=dn, dsaid=dsaId, arg=arg, val=i[2][1],d=diff_out)
                                else:
                                    self.add_value_ldif(o=out, ope='replace', dn=dn, dsaid=dsaId, arg=arg, val=i[2][1])
                        except AttributeError:
                            dsa_dict[dn][arg] = i[2][1]
                            if write_cmnd:
                                self.add_value_ldif(o=out, ope='replace', dn=dn, dsaid=dsaId, arg=arg, val=i[2][1],d=diff_out)
 
            elif i[0] == 'remove':
                # of.writelines("\n")
                
                if i[1] == '':
                    op = 'REMOVE EXTRA DN'
                    
                    for k2 in i[2]:
                        temp=("Operation : {0}{1}DN    : {2}dsaId={3}\n").format(op, ' ' * (50 - len(op)), dn, dsaId)
                        diff_out.writelines(temp)
                        for k3 in k2[1].keys():
                            if k3 == 'def': continue
                            diff_out.writelines("Attribute : {0}{1}Value : {2}\n".format(k3, ' ' * (50 - len(k3)), k2[1][k3]))
                        diff_out.writelines("\n")
                else:
                    op = 'REMOVE EXTRA VALUES FROM DN'
                    try:
                        dn, arg = i[1].split('.')
                        temp=("Operation : {0}{1}DN    : {2}dsaId={3}\n").format(op, ' ' * (50 - len(op)), dn, dsaId)
                        diff_out.writelines(temp)
                        for x in i[2]:
                            
                              
                            if write_cmnd:
                                self.remove_value_ldif(o=out, dn=dn, dsaid=dsaId, arg=arg,val=x[0],d=diff_out)
                    except:
                        if type(i[1]) == list:                            
                            dn = i[1][0]
                        else:
                            dn = i[1]
                        temp=("Operation : {0}{1}DN    : {2}dsaId={3}\n").format(op, ' ' * (50 - len(op)), dn, dsaId)
                        diff_out.writelines(temp)                            
                        for k4 in i[2]:
    
                            if write_cmnd:
                                self.remove_value_ldif(o=out, dn=dn, dsaid=dsaId, arg=k4[0],val=k4[1],d=diff_out)
                    diff_out.writelines("\n")
        if write_cmnd:
            out.close()
        diff_out.close()
    def generate_difference(self,result,name,dsaId):
        exc=[]
        res=[]
        #rd=open('try.txt','w')
        for i in result:
            res.append(i)
            #rd.writelines(i)
            
            if 'soapUrlList:' not in i[1] and'users:' not in i[1]:
                    '''
                    tmp=[]
                    tmp.append(i[0])
                    tmp.append(i[1]+dsaId)
                    tmp.append(i[2:])
                    print(tmp)'''
                    exc.append(i)
            
        #rd.close()
        df=pd.DataFrame(res)
        df.columns=["Operation","DN","Attribute: Value"]
        df.to_csv(name+"_diff.csv",index=False)
        
        
        
    def get_difference(self, live, non_live, write):
        base = os.path.dirname(live)
        d1 = self.read_dsa(file=live, write_to_file=False)
        for file in non_live:
            name = os.path.join(base, os.path.basename(file).split('.')[0])
            d2 = self.read_dsa(file=file, write_to_file=False)
            dsaId = d2['def']
            result = dd.diff(d2, d1)
            #print(list(result))
            self.validate_diff(d=result, dsa_dict=d2, name=name, dsaId=dsaId, write_cmnd=write)
            #result_2=dd.diff(d2, d1)
            #self.generate_difference(result_2,name,dsaId=dsaId)
 


def main():
    version = '5.1'
    root = Audit(v=version)
    root.title("5G_SCvT")
    #root.iconphoto(True, PhotoImage(file='icon.png'))
    width = 500
    height = 350
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width / 2) - (width / 2)
    y = (screen_height / 2) - (height / 2)
    root.geometry("%dx%d+%d+%d" % (width, height, x, y))
    root.resizable(0, 0)
    root.mainloop()


if __name__ == "__main__":
    version = '5.1'
    c_time = datetime.datetime.now()
    #log_file = os.path.join(os.getcwd(), 'Logs', 'SCvT_logs_{0}.txt'.format(c_time.strftime("%Y%m%d_%H%M%S")))
    #sys.stdout = open(log_file, 'w')
    if os.getcwd() not in sys.path:
        sys.path.append(os.getcwd())
    print("#" * 40)
    print("#         Welcome to SCvT Tool         #")
    print("#" * 40)
    print("\nLogging started......\nDate and Time: {0}\n\n".format(c_time.strftime("%d-%m-%Y %H:%M:%S")))
    print("-" * 40)
    print("|           Version ---> {}           |".format(version))
    print("-" * 40)
    try:
        main()
    except Exception as e:
        messagebox.showerror(message=e)
        raise
    sys.stdout.close()
    #sys.stdout.closed = sys.stderr.closed = False
