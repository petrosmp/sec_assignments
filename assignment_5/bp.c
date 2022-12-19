#include <stdio.h>
#include <net/if.h>
int main(int argc, char *argv[])
{
int i;
struct if_nameindex *ifs = if_nameindex();
if (ifs == NULL) { perror("could not run if_nameindex");return 1;}
for (i=0; (ifs[i].if_index != 0)&&(ifs[i].if_name != NULL); i++)
{
printf("%3d %3d %s\n", i, ifs[i].if_index,ifs[i].if_name);
}
if_freenameindex(ifs);
}