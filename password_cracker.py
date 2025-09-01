#!/usr/bin/env python3
import argparse
import sys
import os
import hashlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class PasswordCracker:
    def __init__(self):
        self.hash_types = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'ntlm': self.ntlm_hash
        }
        self.results = {}
        self.cracked_count = 0
        self.total_count = 0
        
    def ntlm_hash(self, data):
        """NTLM хеш для Windows"""
        return hashlib.new('md4', data.encode('utf-16le')).hexdigest()
    
    def hash_password(self, password, hash_type):
        """Хеширование пароля"""
        if hash_type == 'ntlm':
            return self.hash_types[hash_type](password)
        else:
            return self.hash_types[hash_type](password.encode()).hexdigest()
    
    def load_wordlist(self, wordlist_path):
        """Загрузка словаря"""
        if not os.path.exists(wordlist_path):
            print(f"[-] Wordlist not found: {wordlist_path}")
            return []
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(words)} words from {wordlist_path}")
            return words
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            return []
    
    def load_hashes(self, hash_file):
        """Загрузка хешей из файла"""
        hashes = []
        try:
            with open(hash_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        hashes.append(line)
            print(f"[+] Loaded {len(hashes)} hashes from {hash_file}")
        except Exception as e:
            print(f"[-] Error loading hashes: {e}")
        
        return hashes
    
    def crack_hash(self, target_hash, hash_type, wordlist, max_workers=4):
        """Взлом одного хеша"""
        print(f"[+] Cracking hash: {target_hash[:16]}... ({hash_type})")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for word in wordlist:
                future = executor.submit(self.check_password, word, target_hash, hash_type)
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    duration = time.time() - start_time
                    print(f"[+] CRACKED: {target_hash} -> {result} (in {duration:.2f}s)")
                    return result
        
        print(f"[-] Failed to crack: {target_hash}")
        return None
    
    def check_password(self, password, target_hash, hash_type):
        """Проверка пароля"""
        try:
            hashed = self.hash_password(password, hash_type)
            if hashed.lower() == target_hash.lower():
                return password
        except:
            pass
        return None
    
    def detect_hash_type(self, hash_string):
        """Определение типа хеша"""
        length = len(hash_string)
        
        if length == 32:
            return 'md5'
        elif length == 40:
            return 'sha1'
        elif length == 64:
            return 'sha256'
        elif length == 128:
            return 'sha512'
        else:
            return 'unknown'
    
    def crack_hashes(self, hashes, hash_type, wordlist, max_workers=4):
        """Взлом множества хешей"""
        print(f"[+] Starting password cracking for {len(hashes)} hashes...")
        
        self.total_count = len(hashes)
        self.cracked_count = 0
        
        results = {}
        
        for target_hash in hashes:
            if hash_type == 'auto':
                detected_type = self.detect_hash_type(target_hash)
                if detected_type == 'unknown':
                    print(f"[-] Unknown hash type for: {target_hash}")
                    continue
                hash_type = detected_type
            
            result = self.crack_hash(target_hash, hash_type, wordlist, max_workers)
            if result:
                results[target_hash] = result
                self.cracked_count += 1
        
        self.results = results
        return results
    
    def save_results(self, output_file):
        """Сохранение результатов"""
        try:
            with open(output_file, 'w') as f:
                f.write("Hash,Password\n")
                for hash_value, password in self.results.items():
                    f.write(f"{hash_value},{password}\n")
            print(f"[+] Results saved to: {output_file}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def print_summary(self):
        """Вывод сводки"""
        print("\n=== CRACKING SUMMARY ===")
        print(f"Total hashes: {self.total_count}")
        print(f"Cracked: {self.cracked_count}")
        print(f"Success rate: {(self.cracked_count/self.total_count)*100:.1f}%" if self.total_count > 0 else "0%")
        
        if self.results:
            print("\nCracked passwords:")
            for hash_value, password in self.results.items():
                print(f"  {hash_value[:16]}... -> {password}")

def main():
    parser = argparse.ArgumentParser(description='XILLEN Password Cracker')
    parser.add_argument('hashes', help='Hash file or single hash')
    parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file')
    parser.add_argument('-t', '--type', default='auto', 
                       choices=['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'auto'],
                       help='Hash type (default: auto-detect)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-j', '--threads', type=int, default=4, help='Number of threads')
    
    args = parser.parse_args()
    
    cracker = PasswordCracker()
    
    wordlist = cracker.load_wordlist(args.wordlist)
    if not wordlist:
        sys.exit(1)
    
    if os.path.exists(args.hashes):
        hashes = cracker.load_hashes(args.hashes)
    else:
        hashes = [args.hashes]
    
    if not hashes:
        print("[-] No hashes to crack")
        sys.exit(1)
    
    print(f"[+] Starting XILLEN Password Cracker")
    print(f"[+] Hash type: {args.type}")
    print(f"[+] Threads: {args.threads}")
    
    start_time = time.time()
    results = cracker.crack_hashes(hashes, args.type, wordlist, args.threads)
    total_time = time.time() - start_time
    
    print(f"\n[+] Cracking completed in {total_time:.2f} seconds")
    
    cracker.print_summary()
    
    if args.output and results:
        cracker.save_results(args.output)

if __name__ == "__main__":
    main()
