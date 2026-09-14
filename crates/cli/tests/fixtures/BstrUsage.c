typedef wchar_t *BSTR;
void audit(BSTR text, wchar_t *wide, char *narrow) {
    BSTR shifted = text + 1;
    SysFreeString(narrow);
    BSTR casted = (BSTR)wide;
    SysAllocString(text);
}
