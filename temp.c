#include <stdlib.h>
#include <string.h>

    struct student{
    char name [20];
    char surname [20];
    char id_num [10];
    int mark_lab;
    int mark_test;
    };
int main(){
    int i;

    struct student st[]={
        {"AA", "Pu", "1C666", 8, 9},
        {"RR",  "Ab","4DC33",5,7},
        {"AA", "Z","24C25", 10, 6},
        {"KK", "Oz","161RD", 9,10},
        {"EE", "Pre", "DC902", 7,8}
    };

  //to sort the array
   for (i=0;i<4;i++){
        if (st[3]->mark_lab<st[i]->mark_lab){
            st[3]->name=st[i]->name;
            st[3]->surname=st[i]->surname;
            st[3]->id_num=st[i]->surname;
            st[3]->mark_lab=st[i]->mark_lab;
            st[3]->mark_test=st[i]->mark_lab;

            stu[i]->name=stu[i+1]->name;
            stu[i]->surname=stu[i+1]->surname;
            stu[i]->id_num=stu[i+1]->surname;
            stu[i]->mark_lab=stu[i+1]->mark_lab;
            stu[i]->mark_test=stu[i+1]->mark_lab;

            stu[i+1]->name=stu[3]->name;
            stu[i+1]->surname=stu[3]->surname;
            stu[i+1]->id_num=stu[3]->surname;
            stu[i+1]->mark_lab=stu[3]->mark_lab;
            stu[i+1]->mark_test=stu[3]->mark_lab;
        }
    }

    //to print it on the screen
    for (i=0;i<4;i++){
        printf (printf("\nName: %s, Surname: %s, ID: %s, Lab_Mark: %d, Test Mark: %d",
         stu[i]->name, stu[i]->surname,stu[i]->id_num, stu[i]->mark_lab,stu[i]->mark_test);
    }

    return 0;
}
