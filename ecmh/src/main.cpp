#include "ecmh.hpp"
void equaltest(ecmh ecmh1,ecmh ecmh2);
int main(){
    ecmh ecmh1,ecmh2;

    printf("-------------------------- Init test --------------------------\n");
    vector<int> vec1= {1,2,4,5,6,7};
    vector<int> vec2= {1,2,4,5,6,7};
    ecmh1.init(vec1);
    ecmh2.init(vec2);
    equaltest(ecmh1,ecmh2);

    printf("--------------------- Add test(single int) ---------------------\n");
    ecmh1.add(1);
    ecmh1.add(2);
    ecmh1.add(4);
    equaltest(ecmh1,ecmh2);

    printf("--------------------- Add test(vector int) ---------------------\n");
    vector<int> addvec = {1,2,4};
    ecmh2.add(addvec);
    equaltest(ecmh1,ecmh2);

    printf("-------------------- Erase test(single int) --------------------\n");
    ecmh2.erase(5);
    ecmh2.erase(6);
    ecmh2.erase(7);
    equaltest(ecmh1,ecmh2);

    printf("-------------------- Erase test(vector int) --------------------\n");
    vector<int> erasevec = {5,6,7};
    ecmh1.erase(erasevec);
    equaltest(ecmh1,ecmh2);

    printf("------------------- Operator test(vector int) ------------------\n");
    ecmh1 += 12;
    equaltest(ecmh1,ecmh2);
    ecmh1 -= 12;
    equaltest(ecmh1,ecmh2);

    printf("-------------------- Empty test(vector int) --------------------\n");
    ecmh1.empty();
    ecmh2.empty();
    equaltest(ecmh1,ecmh2);
    
}

void equaltest(ecmh ecmh1,ecmh ecmh2){
    printf("set1:");ecmh1.printHash();
    printf("set2:");ecmh2.printHash();
    if(ecmh1 == ecmh2) printf("Equal\n");
    else printf("Unequal\n");
}