// Copyright (c) 2022 Jason Lich

// code "inspired" by: https://github.com/jsimonetti/pwscheme/blob/4d9895f5db73/md5crypt/md5crypt.go

package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"strings"
)

const usageFmt string = "usage: %v password salt|md5crypt\n"

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var md5CryptSwaps = [16]int{12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11}

var magic = []byte("$1$")

func main() {
	if len(os.Args) < 3 {
		fmt.Printf(usageFmt, os.Args[0])
		os.Exit(1)
		return
	}
	password := string(os.Args[1])
	if len(password) < 1 {
		fmt.Printf(usageFmt, os.Args[0])
		os.Exit(2)
		return
	}
	salt := string(os.Args[2])
	if len(salt) < 1 {
		fmt.Printf(usageFmt, os.Args[0])
		os.Exit(3)
		return
	}
	
	var hash string
	
	if len(salt) > 3 && string(salt[:3]) == "$1$" {
		salt = salt[3:]
		s := strings.LastIndex(salt,"$")
		if s < 0 && len(salt) > s+1 {
			fmt.Printf("error: invalid md5crypt string\n")
			fmt.Printf(usageFmt, os.Args[0])
			os.Exit(3)
			return
		}
		hash = salt[s+1:]
		salt = salt[:s]
	}
	
	if len(salt) > 8 {
		fmt.Printf("error: salt must be less than 8 characters\n")
		fmt.Printf(usageFmt, os.Args[0])
		os.Exit(4)
		return
	}
	
	for strings.Count(string(salt), "$") != 0 {
		fmt.Printf("error: salt can not contain $\n")
		fmt.Printf(usageFmt, os.Args[0])
		os.Exit(5)
		return
	}
	
	if len(hash) > 0 {
		cryptout := crypt([]byte(password), []byte(salt))
		if (string(cryptout) == "$1$"+salt+"$"+hash) {
			fmt.Printf("MATCH %s\n", crypt([]byte(password), []byte(salt)))
		} else {
			fmt.Printf("FAIL %s\n", crypt([]byte(password), []byte(salt)))
		}
	} else {
		fmt.Printf("%s\n", crypt([]byte(password), []byte(salt)))
	}
}

func crypt(password, salt []byte) []byte {

	d := md5.New()

	d.Write(password)
	d.Write(magic)
	d.Write(salt)

	d2 := md5.New()
	d2.Write(password)
	d2.Write(salt)
	d2.Write(password)

	for i, mixin := 0, d2.Sum(nil); i < len(password); i++ {
		d.Write([]byte{mixin[i%16]})
	}

	for i := len(password); i != 0; i >>= 1 {
		if i&1 == 0 {
			d.Write([]byte{password[0]})
		} else {
			d.Write([]byte{0})
		}
	}

	final := d.Sum(nil)

	for i := 0; i < 1000; i++ {
		d2 := md5.New()
		if i&1 == 0 {
			d2.Write(final)
		} else {
			d2.Write(password)
		}

		if i%3 != 0 {
			d2.Write(salt)
		}

		if i%7 != 0 {
			d2.Write(password)
		}

		if i&1 == 0 {
			d2.Write(password)
		} else {
			d2.Write(final)
		}
		final = d2.Sum(nil)
	}

	result := make([]byte, 0, 22)
	v := uint(0)
	bits := uint(0)
	for _, i := range md5CryptSwaps {
		v |= (uint(final[i]) << bits)
		for bits = bits + 8; bits > 6; bits -= 6 {
			result = append(result, itoa64[v&0x3f])
			v >>= 6
		}
	}
	result = append(result, itoa64[v&0x3f])

	return append(append(append(magic, salt...), '$'), result...)
}
