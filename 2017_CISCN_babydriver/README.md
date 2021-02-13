# info
kernel_base
0xffffffff81000000

modules
0xffffffffc0000000
0xffffffffc0002440 => bss

0xffffffffc00024d0
1. 0xffff880003c73c00
2. 0xffff880003c733c0

## analysis
``` c
struct Device {
	char *device_buf;
	uint64_t device_buf_len;
} babydev_struct;

void open(inode *inode, file *filp)
{
	// open 時用 kmalloc create 0x40 大小的空間，並且存在
	// kmalloc() 底層是 kmem_cache_alloc_trace()
	babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 0x40LL);
	babydev_struct.device_buf_len = 64LL;	
}

void read(file *filp, char *buffer, size_t length, loff_t *offset)
{
	if ( !babydev_struct.device_buf ) // 如果當前沒有 device
	  	return -1LL;
	result = -2LL;
	if ( babydev_struct.device_buf_len > v4 )
	{
	  v6 = v4;
	  copy_to_user(buffer);
	  result = v6;
	}
}

void write(file *filp, const char *buffer, size_t length, loff_t *offset)
{
	if ( !babydev_struct.device_buf ) // 如果當前沒有 device
	  	return -1LL;
	result = -2LL;
	if ( babydev_struct.device_buf_len > v4 )
	{
	  v6 = v4;
	  copy_from_user(babydev_struct.device_buf, (void *)buffer, (void *)v4);
	  result = v6;
	}
}

void ioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
	if ( command == 0x10001 ) // 如果 command 是 0x10001，就重新 allocate device
	{
	  kfree(babydev_struct.device_buf);
	  babydev_struct.device_buf = (char *)_kmalloc(v4, 0x24000C0LL);
	  babydev_struct.device_buf_len = v4;
	  printk("alloc done\n");
	  result = 0LL;
	}
	else
	{
	  printk(&unk_2EB);
	  result = -22LL;
	}
}
void release(inode *inode, file *filp)
{
	kfree(babydev_struct.device_buf); // free device buffer
}
```


