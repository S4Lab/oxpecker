VM_NAME="nitro_ubuntu1604"
a=0
while true; do
    ./main.py $VM_NAME
    a=`expr $a + 1`
    if [ $a -eq 1000 ]
    then
        break
    fi
    sleep 0.1
done
