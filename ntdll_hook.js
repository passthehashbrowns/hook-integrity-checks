
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function doItAll(){
    var pNtOpenProcess = Module.findExportByName('ntdll.dll', 'NtOpenProcess');
    Interceptor.attach(pNtOpenProcess, {
        onEnter: function (args) {
            send("[+] Called NtOpenProcess")
        }
    });

    await sleep(1)
    var hookedBytes = Instruction.parse(pNtOpenProcess)
    send("[*] Hooked bytes: " + hookedBytes.toString())
    while(true){
        await sleep(1000);
        var instruction = Instruction.parse(pNtOpenProcess)
        if(instruction.toString() != hookedBytes.toString()){
            send("[!] Function appears to be unhooked!")
        }
    }
}

doItAll()
