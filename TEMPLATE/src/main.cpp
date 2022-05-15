#include <vector>
#include "head.h"

using std::cout;
using std::endl;
using std::vector;

int main(int argc, char*argv[]) {
    std::cout<<"project template"<<std::endl;
    vector<int> vec_test{1,2,3,4,5};
    for(const auto& i : vec_test){
        cout<<i<<' ';
    }
    cout<<endl;
    return 0;
}