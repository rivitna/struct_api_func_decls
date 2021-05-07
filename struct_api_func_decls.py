import sys
import io
import os.path
import idautils
import idaapi


DELIMS = { ' ', '\t' }
FUNC_NAME_PREFIX = ''


def load_func_decl_list():
    func_decl_list = {}

    file_name = os.path.join(os.path.dirname(__file__), 'apifuncs.txt')
    with io.open(file_name, 'rt') as f:
        for line in f:
            s = line.strip()
            i = next((i for i, ch in enumerate(s) if ch in DELIMS), None)
            if (i is None):
                continue

            fn_name = FUNC_NAME_PREFIX + s[:i].strip()
            fn_decl = s[i + 1:].strip()
            if (fn_name != '') and (fn_decl != ''):
                func_decl_list[fn_name] = fn_decl

    return func_decl_list


def set_struct_func_decls(strid, strname, func_decl_list):
    count = 0

    struc = ida_struct.get_struc(strid)

    for mem_entry in StructMembers(strid):
        fn_decl = func_decl_list.get(mem_entry[1])
        if (fn_decl is None):
            continue

        success = False

        memid = ida_struct.get_member_id(struc, mem_entry[0])
        if (memid != BADADDR):
            pt = parse_decl(fn_decl, PT_SIL)
            if pt is not None:
                if apply_type(memid, pt, TINFO_DEFINITE):
                    success = True

        if success:
            count += 1
            print('Structure member \"%s.%s\" type is set.' %
                      (strname, mem_entry[1]))
        else:
            print('Unable to set type to structure member \"%s.%s\".' %
                      (strname, mem_entry[1]))

    return count


print('Loading API function declarations...')
func_decl_list = load_func_decl_list()
print(str(len(func_decl_list)) + ' API function declarations loaded.')

if func_decl_list:
    count = 0

    for struct_entry in Structs():
        count += set_struct_func_decls(struct_entry[1], struct_entry[2],
                                       func_decl_list)

    print(str(count) + ' structure member types is set.')
