#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include "common.h"
#include <linux/export.h>
#include <linux/path.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <crypto/md5.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>


asmlinkage extern long (*sysptr)(void *arg);
static int is_regular_file(struct file *fp);
static int is_same_file(struct file *fp1, struct file *fp2);
static int is_file_exists(const char *name);
static int read_write_file(struct filename *f1name, struct filename *f2name, unsigned char *key, int flag);
static int encrypt_decrypt_file(char *buf, unsigned char *key, int len, int flag);
static int add_preamble(struct file *fp, unsigned char *key, int len);
static int verify_preamble(struct file *fp, unsigned char *key, int len);
static int delete_partial_file(struct file *fp);
static int rename_temp_file(struct file *fp_old, struct file *fp_new);
unsigned char *key_to_hash(unsigned char *key);


static int verify_preamble(struct file *fp, unsigned char *key, int len)
{
	int rc;
	unsigned char *verify_key= NULL;
	unsigned char *keyHash= NULL;
	mm_segment_t fs;

	keyHash = key_to_hash(key);
	if(!keyHash){
		printk("Error in hashing userland key while verifying preamble\n");
		rc = -ENOKEY;
		goto out;
	}

	verify_key=kmalloc(len,GFP_KERNEL);
	if(IS_ERR(verify_key)){
                printk("Error in allocating memory to temp Key\n ");
                rc = -PTR_ERR(verify_key);
                goto out;
	}

	fs=get_fs();
	set_fs(get_ds());

	rc = fp->f_op->read(fp,verify_key,len,&fp->f_pos);
	if(rc < 0){
		printk("Failed to read key while decryption\n");
		set_fs(fs);
		rc= -EIO;
		goto out;
	}
	set_fs(fs);

	rc = memcmp((void*)verify_key,(void*)keyHash,len);
	
	if(rc != 0)
	{
		printk("Key mismatched \n");
		rc= -EKEYREJECTED;
	}
out:
	if(verify_key)
		kfree(verify_key);
	if(keyHash)
		kfree(keyHash);
	return rc;

}


static int add_preamble(struct file *fp, unsigned char *key, int len)
{
	int rc;
	unsigned char *keyHash = NULL;

	mm_segment_t fs;

        keyHash = key_to_hash(key);
        if(!keyHash){
                printk("Error in hashing userland key while adding preamble\n");
                rc = -ENOKEY;
                goto out;
        }	

	fs=get_fs();
        set_fs(get_ds());

	rc = fp->f_op->write(fp,keyHash,len,&fp->f_pos);
	if(rc < 0){
                printk("Failed to store key while encryption\n");
                set_fs(fs);
                rc= -EIO;
                goto out;
        }
        set_fs(fs);
out:	
	if(keyHash)
		kfree(keyHash);
	return rc;
}


unsigned char * key_to_hash(unsigned char *key)
{
	struct scatterlist sg;
    	struct crypto_hash *tfm;
    	struct hash_desc desc;
	unsigned char *digest= NULL;
	
	digest=kmalloc(16,GFP_KERNEL);
	if(IS_ERR(digest)){
                printk("Error in allocating memory to Hash Key\n ");
                return NULL;
      	}

    	tfm = crypto_alloc_hash("md5", 0, 0);

    	desc.tfm = tfm;
    	desc.flags = 0;

    	sg_init_one(&sg, key, 16);
    	
	crypto_hash_init(&desc);
	crypto_hash_update(&desc, &sg, 16);
    	crypto_hash_final(&desc, digest);

	crypto_free_hash(tfm);

	if(!digest){
                printk("Error in hashing userland key\n");
                return NULL;
        }
    	return digest;
}


static int encrypt_decrypt_file(char *buf, unsigned char *key, int len, int flag)
{
	struct crypto_blkcipher *blkcipher = NULL;
	char *cipher = "ctr(aes)";

	struct scatterlist sg;
	struct blkcipher_desc desc;
	int rc;

	blkcipher = crypto_alloc_blkcipher(cipher, 0, 0);
	if (IS_ERR(blkcipher)) {
		printk("could not allocate blkcipher handle for %s\n", cipher);
		rc= -PTR_ERR(blkcipher);
		goto out;
	}

	if (crypto_blkcipher_setkey(blkcipher, key, 16)) {
		printk("key could not be set\n");
		rc = -EAGAIN;
		goto out;
	}

	desc.flags = 0;
	desc.tfm = blkcipher;
	sg_init_one(&sg, buf, len);

	/* encrypt data */
	if(flag == 1)
	{
		rc = crypto_blkcipher_encrypt(&desc, &sg, &sg, len);
		if(rc){
			printk("Encryption failed \n");
			rc = -EFAULT;
			goto out;
		}
	}

	/* decrypt data */
	else if(flag == 0)
        {
                rc = crypto_blkcipher_decrypt(&desc, &sg, &sg, len);
                if(rc){
                        printk("Decryption failed \n");
			rc = -EFAULT;
			goto out;
                }
        }

	return 0;

out:
	if (blkcipher)
		crypto_free_blkcipher(blkcipher);
	return rc;
}


static int is_same_file(struct file *fp1, struct file *fp2)
{
	struct inode *i1, *i2;
	i1 = fp1->f_inode;
	i2 = fp2->f_inode;
	if(i1->i_ino == i2->i_ino)
		return 1;
	else
		return 0;
}


static int is_regular_file(struct file *fp)
{	
	int rc;
	struct inode *i;

	i = fp->f_inode;
	rc = !S_ISREG(i->i_mode);
	return rc;
}


static int is_file_exists(const char *name)
{
	mm_segment_t fs;
	int rc;
	struct kstat stat;
	fs=get_fs();
	set_fs(get_ds());
	rc =!vfs_stat(name, &stat);
	//printk("file existes rc = %d \n",rc);
	set_fs(fs);
	return rc;
}
	
				
static int delete_partial_file(struct file *fp)
{
	int rc;
	struct dentry *d = fp->f_path.dentry;
	struct inode *pi = fp->f_path.dentry->d_parent->d_inode;

	struct dentry *pd = NULL;
	dget(d);
	pd= dget_parent(d);
	mutex_lock_nested(&pd->d_inode->i_mutex,I_MUTEX_PARENT);
	
	rc= vfs_unlink(pi,d,NULL);
	if(rc){
		printk("Error in vfs_unlink() \n");
		rc= -ECANCELED;
		goto out;
	}
	
out:
	mutex_unlock(&pd->d_inode->i_mutex);
	dput(pd);
	dput(d);
	printk("rc = %d\n",rc);
	return rc;
}																																																			
static int rename_temp_file(struct file *fp_old, struct file *fp_new)
{
	int rc;
	struct inode *pi_old = fp_old->f_path.dentry->d_parent->d_inode;
	struct inode *pi_new = fp_new->f_path.dentry->d_parent->d_inode;
	
	struct dentry *d_old = fp_old->f_path.dentry;
	struct dentry *d_new = fp_new->f_path.dentry;
	
	struct dentry *pd_old = NULL;
	struct dentry *pd_new = NULL;
	struct dentry *trap = NULL;
	
	dget(d_old);
	dget(d_new);
	pd_old=dget_parent(d_old);
	pd_new=dget_parent(d_new);

	trap = lock_rename(pd_old,pd_new);

	if(trap == d_old){
		rc = -EINVAL;
		goto out;
	}

	if(trap == d_new){
		rc = -ENOTEMPTY;
		goto out;
	}

	rc = vfs_rename(pi_old,d_old,pi_new,d_new,NULL,0);
	if(rc){
		printk("Error in vfs_rename() \n");
		rc= -ECANCELED;
		goto out;
	}

out:
	unlock_rename(pd_old,pd_new);
	dput(pd_new);
	dput(pd_old);
	dput(d_new);
	dput(d_old);
	
	return rc;
}


static int read_write_file(struct filename *f1name, struct filename *f2name, unsigned char *key, int flag)
{
	struct file *fp1 =NULL;	
	struct file *fp2 =NULL;
	struct file *fp_temp = NULL;
	int rbytes, wbytes;
	char *buf = NULL;
	int keylen =16;
	int rc;
	int flag_outfile, flag_delete_temp;
	mm_segment_t fs;

	flag_outfile =0;
	flag_delete_temp =0;
	fp1 = filp_open(f1name->name,O_RDONLY,0);
	putname(f1name);
	
	if(!fp1)
	{
		printk("Error opening input file \n");
		rc = -ENOENT;
		return rc;			
	}
	
	if(IS_ERR(fp1))
	{
		printk("Error opening input file \n");
		rc = -ENOENT;
		return rc;
	}
	
	rc = is_regular_file(fp1);
	if(rc){
		printk("Input file is not regular \n");
		rc = -EISDIR;
		goto out;
	}
	
	if(!fp1->f_op){
		printk("Permission Denied \n");
		rc = -EPERM;
		goto out;
	}

	if(!fp1->f_op->read){
		printk("Read operation not permitted \n");
		rc = -EPERM;
		goto out;
	}

	flag_outfile = is_file_exists(f2name->name);
	
	if(flag_outfile)
		fp2 = filp_open(f2name->name,O_WRONLY ,fp1->f_mode);
	else
		fp2 = filp_open(f2name->name,O_CREAT | O_WRONLY ,fp1->f_mode);

	fp_temp = filp_open(strcat((char *)f2name->name,".tmp"),O_CREAT | O_WRONLY,fp1->f_mode);

	putname(f2name);

	if(!fp2 || !fp_temp){
		printk("Error opening write file\n");
		rc= -ENOENT;
		return rc;
	}

	if(IS_ERR(fp2) || IS_ERR(fp_temp)){
		printk("Error opening write file\n");
		rc= -ENOENT;
		return rc;
	}

	if(!fp2->f_op || !fp2->f_op){
                printk("Permission Denied \n");
                rc = -EPERM;
                goto out;
        }

        if(!fp2->f_op->write || !fp2->f_op->write){
                printk("Write operation not permitted \n");
                rc = -EPERM;
                goto out;
        }
	
	rc = is_same_file(fp1,fp2);
        if(rc){
                printk("Input and output files are same \n");
                rc = -EINVAL;
                goto out;
        }
	
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(IS_ERR(buf)){
		printk("Error while allocationg temporary buffer for reading and writing \n");
                rc = -PTR_ERR(key);
                goto out;
        }

	/* Add info about key in preamble during encryption */
	if(flag == 1)
	{	
		rc=add_preamble(fp_temp,key,keylen);
		if(rc< 0){
			printk("Error adding preamble to the outfile\n");
			goto out;
		}
	}

	/* Verify hashed key stored in preamble during decryption */
	if(flag == 0)
	{
		rc=verify_preamble(fp1,key,keylen);
		if(rc<0){
			printk("Error verifying preamble in the encrypted file\n");
			goto out;
		}
	}
	
	/* read and write actual data */
	while(1){
		fs=get_fs();
		set_fs(get_ds());
		
		rbytes = fp1->f_op->read(fp1,buf,PAGE_SIZE,&fp1->f_pos);
		
		if(rbytes < 0){
			printk("Failed reading input file\n");
			set_fs(fs);
			rc= -EIO;
			goto out;
		}

		if (rbytes == 0){
			printk("Reached end of file while reading \n");
			rc= 0;
			goto out_rename;
		}
		
		/* If flag is set as 1, input file is encrypted */
		if(flag == 1){
			rc=encrypt_decrypt_file(buf,key,rbytes,flag);
			if(rc < 0){
				printk("Encrypt failure\n");
				goto out;
			}
		}
		/* If flag is set as 0, input file is decrypted */
		else if(flag == 0){
			rc=encrypt_decrypt_file(buf,key,rbytes,flag);
			if(rc < 0){
				printk("Decrypt failure \n");
				goto out;
			}
		}

		wbytes = fp_temp->f_op->write(fp_temp,buf,rbytes,&fp_temp->f_pos);
		
		if(wbytes < 0){
			printk("Failed writing output file\n");
                        set_fs(fs);
                        rc= -EIO;
                        goto out;
		}
		set_fs(fs);
	}
	
out_rename:
	flag_delete_temp=1;
	rc = rename_temp_file(fp_temp,fp2);
	if(rc)
		printk("Rename operation failed \n");

out:	
	if(flag_delete_temp==0){
		if(rc<0){
			if(delete_partial_file(fp_temp))
				printk("Deleting partial temp file failed \n");
		}
	}
	printk("flag_outfile = %d \n",flag_outfile);
	if(flag_outfile==0){
		if(rc < 0){
			if(delete_partial_file(fp2))
				printk("Deleting out file failed\n");
        	}
	}
	if(fp_temp)
		filp_close(fp_temp,NULL);
	if(buf)
		kfree(buf);
	if(fp2)
		filp_close(fp2,NULL);
	if(fp1)
		filp_close(fp1,NULL);
	if(IS_ERR(f2name))
		putname(f2name);
	if(IS_ERR(f1name))
		putname(f1name);
	return rc;
}


asmlinkage long xcrypt(void *arg)
{
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	
	struct inputs *mptr= NULL;

	struct filename *infile= NULL;
	struct filename *outfile= NULL; 
	char *key= NULL;

	int rc;
	printk("xcrypt received arg %p\n", arg);
	if (arg == NULL)
		return -EINVAL;

	mptr = kmalloc(sizeof(struct inputs),GFP_KERNEL);
	if(IS_ERR(mptr)){
		printk("Error in allocating memory to input structure\n ");
		rc = -PTR_ERR(mptr);
		goto out;
	}
	
	rc= copy_from_user(mptr,arg,sizeof(struct inputs));
	if(rc){
		printk("Error in copying inputs from user \n");
		rc= -EFAULT;
		goto out;
	}
		
	infile= getname(mptr->in);
	if(IS_ERR(infile)){
		printk("getname() failed for filename of input file\n");
		rc= -PTR_ERR(infile);
		goto out;
	}

	outfile= getname(mptr->out);
	if(IS_ERR(outfile)){
		printk("getname() failed for filename of output file\n");
		rc= -PTR_ERR(outfile);
		goto out;
	}

	key= kmalloc(mptr->keylen,GFP_KERNEL);
	if(IS_ERR(key)){
		printk("Error allocating memory to key \n");
                rc = -PTR_ERR(key);
                goto out;
        }

	rc= copy_from_user(key,(char*)mptr->keybuf,mptr->keylen);
 	if(rc){
		printk("Error copying key to kernel space \n");
                rc=-EFAULT;
                goto out;
        }
	
	rc= read_write_file(infile,outfile,(void*)key,mptr->flag);
	if(rc < 0){
		printk("Syscall xcrypt failed with error= %d \n",rc);
	}
	else{
		printk("Successfully returned from syscall xcrypt\n");
	}
out: 
	if(key)
		kfree(key);
	if(IS_ERR(outfile))
		putname(outfile);
	if(IS_ERR(infile))
		putname(infile);
	if(mptr)
		kfree(mptr);
	return rc;

}


static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}


static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}


module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SHUBHI RANI, 110455118, FALL 2015");
MODULE_DESCRIPTION("File Encryption System Call");
