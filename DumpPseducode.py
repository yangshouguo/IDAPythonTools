#encoding=utf-8
"""
Python2.7
IDAPython script running with Hexray plugin !!!
usage: idat -SDumpPseudocode.py binary|binary.idb
save pseudocdes to file
"""

import idautils
import idaapi
from idc import *
from idaapi import *
from idautils import *
import logging,os,sys
l = logging.getLogger("DumpPseducode")
l.addHandler(logging.FileHandler("DumpPseducode.log"))
l.setLevel(logging.ERROR)
root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root)
import pickle

#---- prepare environment
def wait_for_analysis_to_finish():
    '''
    :return:
    '''
    l.info('[+] waiting for analysis to finish...')
    idaapi.autoWait()
    idc.Wait()
    l.info('[+] analysis finished')

def load_plugin_decompiler():
    '''
    load the hexray plugins
    :return: success or not
    '''
    is_ida64 = GetIdbPath().endswith(".i64")
    if not is_ida64:
        idaapi.load_plugin("hexrays")
        idaapi.load_plugin("hexarm")
    else:
        idaapi.load_plugin("hexx64")
    if not idaapi.init_hexrays_plugin():
        l.error('[+] decompiler plugins load failed. IDAdb: %s' % GetInputFilePath())
        idc.Exit(0)

wait_for_analysis_to_finish()
load_plugin_decompiler()

#-----------------------------------

#--------------------------
spliter = "************"
class Visitor(idaapi.ctree_visitor_t):
    #preorder traversal tree
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST|idaapi.CV_INSNS)
        self.cfunc = cfunc

    def get_pseudocode(self):
        sv = self.cfunc.get_pseudocode()
        code_lines = []
        for sline in sv:
            code_lines.append(tag_remove(sline.line))
        return "\n".join(code_lines)

class AstGenerator():

    def __init__(self, file_to_save = ""):
        '''
        '''
        self._file_to_save = file_to_save

    def run(self, fn, specical_name = ""):
        '''
        :param fn: a function to handle the functions in binary
        :return:
        '''
        for i in range(0, get_func_qty()):
            func = getn_func(i)
            segname = get_segm_name(getseg(func.startEA))
            if segname[1:3] not in ["OA", "OM", "te", "_t"]:
                continue
            func_name = GetFunctionName(func.startEA)
            try:
                pseudocode = fn(func)
                self.save_psudocode(func_name, pseudocode)
                # l.error("AST_TREE:"+type(ast_tree))
            except Exception,e:
                l.error(e)

    def save_psudocode(self, func_name, pseudocode):
        with open(self._file_to_save, "a") as f:
            f.write("******[%s]******\n" % func_name)
            f.write(pseudocode)
            f.write("\n\n")


    @staticmethod
    def get_info_of_func(func):
        '''
        :param func:
        :return:
        '''
        try:
            cfunc = idaapi.decompile(func.startEA)
            vis = Visitor(cfunc)
            return vis.get_pseudocode()
        except:
            print("Function %s decompilation failed" % (GetFunctionName(func.startEA)))
            raise


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser("usage: idat -SDumpPseudocode.py binary|binary.idb")
    ap.add_argument("-o","--output", default=GetIdbPath()+"_code.txt", help="file path to save results")
    args = ap.parse_args(idc.ARGV[1:])
    l.info("output: "+ args.output)
    astg = AstGenerator(args.output)
    astg.run(astg.get_info_of_func)
    # astg.run(astg.get_info_of_func, specical_name="SSL_get_ciphers") # this line code for test
    idc.Exit(0)
