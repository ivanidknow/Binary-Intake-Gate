/* Minimal C program to build a Speakeasy-loadable PE (checksec_sample.exe).
 * Compile: gcc -m32 -s -O2 -o checksec_sample.exe return_zero.c
 * Or (64-bit): gcc -s -O2 -o checksec_sample.exe return_zero.c
 * Then build_emulation_payload will inject EICAR into .data via pefile.
 */
char payload[64];  /* .data section for EICAR injection */
int main(void) {
    return 0;
}
