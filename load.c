  #include <windows.h>
  #include <stdio.h>

  int main() {
      HMODULE h = LoadLibraryA("test.dll");
      if (h) {
          FreeLibrary(h);
      } else {
          printf("Failed to load DLL\n");
      }
      return 0;
  }
