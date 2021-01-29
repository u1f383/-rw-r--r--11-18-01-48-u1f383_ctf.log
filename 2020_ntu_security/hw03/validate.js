const fs = require('fs')
const lib = require('../lab03/lib')(require('../lab03/config'))

async function main() {
    let factory_addr = '0x8e0a809B1f413deB6427535cC53383954DBF8329'
    let factory = lib.contract(factory_addr, JSON.parse(fs.readFileSync('BetFactory.abi')))

    let token = '0xafdd757a8ad0241dcb6f307861e19d29ca2f701d3907551dc289b49b3fbce88f'
    await factory.call('validate', token)
}

main()