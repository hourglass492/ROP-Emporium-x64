
int called(unsigned int a,unsigned int b, unsigned int c){

  if(a == 0xcafebabecafebabe && b == 0xd00df00dd00df00d && c == 0xdeadbeefdeadbeef)
    puts("win\n");


  return 1;
}


int main(char ** argv, int argc){

  called( 0xcafebabecafebabe, 0xd00df00dd00df00d, 0xdeadbeefdeadbeef);



  return 1;
}


