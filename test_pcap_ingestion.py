#!/usr/bin/env python3
"""
Unit tests to verify PCAP data ingestion and validation
"""

import os
import glob
import subprocess
from elasticsearch import Elasticsearch
import json

class TestPCAPIngestion:
    def __init__(self):
        self.es = Elasticsearch('http://localhost:9200')
        self.results = []
        
    def log_test(self, test_name, passed, message=""):
        status = "✓ PASS" if passed else "✗ FAIL"
        self.results.append({
            'test': test_name,
            'passed': passed,
            'message': message
        })
        print(f"{status}: {test_name}")
        if message:
            print(f"  → {message}")
    
    def test_1_check_snort_files_are_pcaps(self):
        """Verify that snort.log files are actually PCAP files"""
        test_name = "Snort files are PCAP format"
        snort_files = glob.glob('demo_pcap_upload/2015-*/snort.log.*')
        
        if not snort_files:
            self.log_test(test_name, False, "No snort.log files found in demo_pcap_upload")
            return
        
        # Check first file
        sample_file = snort_files[0]
        result = subprocess.run(['file', sample_file], capture_output=True, text=True)
        file_type = result.stdout
        
        is_pcap = 'pcap' in file_type.lower() or 'capture' in file_type.lower()
        self.log_test(test_name, is_pcap, f"File type: {file_type.strip()}")
        
        return is_pcap
    
    def test_2_check_demo_pcap_exists(self):
        """Verify demo.pcap file exists and is valid"""
        test_name = "demo.pcap exists and is valid PCAP"
        
        if not os.path.exists('pcap/demo.pcap'):
            self.log_test(test_name, False, "pcap/demo.pcap does not exist")
            return False
        
        size = os.path.getsize('pcap/demo.pcap')
        if size == 0:
            self.log_test(test_name, False, "pcap/demo.pcap is empty")
            return False
        
        result = subprocess.run(['file', 'pcap/demo.pcap'], capture_output=True, text=True)
        file_type = result.stdout
        is_pcap = 'pcap' in file_type.lower() or 'capture' in file_type.lower()
        
        self.log_test(test_name, is_pcap, f"Size: {size} bytes, Type: {file_type.strip()}")
        return is_pcap
    
    def test_3_check_elasticsearch_connection(self):
        """Verify Elasticsearch is accessible"""
        test_name = "Elasticsearch connection"
        
        try:
            info = self.es.info()
            version = info.get('version', {}).get('number', 'unknown')
            self.log_test(test_name, True, f"Connected to Elasticsearch {version}")
            return True
        except Exception as e:
            self.log_test(test_name, False, f"Error: {str(e)}")
            return False
    
    def test_4_check_indices_exist(self):
        """Verify expected Zeek indices exist"""
        test_name = "Zeek indices exist"
        
        expected_indices = ['zeek-conn', 'zeek-http', 'zeek-dns', 'zeek-ftp']
        
        try:
            indices = self.es.cat.indices(format='json')
            index_names = [idx['index'] for idx in indices]
            
            missing = [idx for idx in expected_indices if idx not in index_names]
            
            if missing:
                self.log_test(test_name, False, f"Missing indices: {missing}")
                self.log_test("Available indices", True, f"{index_names}")
                return False
            else:
                self.log_test(test_name, True, f"All expected indices found: {expected_indices}")
                return True
        except Exception as e:
            self.log_test(test_name, False, f"Error: {str(e)}")
            return False
    
    def test_5_check_document_counts(self):
        """Verify indices contain documents"""
        test_name = "Indices contain documents"
        
        indices = ['zeek-conn', 'zeek-http', 'zeek-dns', 'zeek-ftp']
        counts = {}
        
        try:
            for index in indices:
                result = self.es.count(index=index)
                count = result['count']
                counts[index] = count
            
            total = sum(counts.values())
            if total == 0:
                self.log_test(test_name, False, "No documents found in any index")
                return False
            
            self.log_test(test_name, True, f"Total documents: {total}")
            for idx, count in counts.items():
                print(f"  → {idx}: {count} documents")
            return True
        except Exception as e:
            self.log_test(test_name, False, f"Error: {str(e)}")
            return False
    
    def test_6_check_data_is_from_pcap(self):
        """Verify data is from actual PCAP, not synthetic"""
        test_name = "Data is from PCAP (not synthetic)"
        
        try:
            # Check for synthetic data markers
            # Synthetic data has specific UIDs like ABC123, XYZ789
            result = self.es.search(index='zeek-conn', query={'match': {'uid': 'ABC123'}}, size=1)
            
            if result['hits']['total']['value'] > 0:
                self.log_test(test_name, False, "Data appears to be synthetic (found test UID 'ABC123')")
                return False
            
            # Check for real data patterns - real UIDs are typically alphanumeric hashes
            result = self.es.search(index='zeek-conn', size=1)
            if result['hits']['total']['value'] > 0:
                sample_doc = result['hits']['hits'][0]['_source']
                uid = sample_doc.get('uid', '')
                
                # Real Zeek UIDs are base62 encoded, usually contain mixed case
                is_real = len(uid) > 6 and any(c.isupper() for c in uid) and any(c.islower() for c in uid)
                
                self.log_test(test_name, is_real, f"Sample UID: {uid}")
                return is_real
            else:
                self.log_test(test_name, False, "No documents found to validate")
                return False
        except Exception as e:
            self.log_test(test_name, False, f"Error: {str(e)}")
            return False
    
    def test_7_check_field_types(self):
        """Verify fields have correct data types"""
        test_name = "Field types are correct"
        
        try:
            mapping = self.es.indices.get_mapping(index='zeek-conn')
            properties = mapping['zeek-conn']['mappings']['properties']
            
            # Check critical fields
            checks = []
            if 'ts' in properties:
                checks.append(('ts', properties['ts']['type'] in ['double', 'float']))
            if 'id.orig_p' in properties:
                checks.append(('id.orig_p', properties['id.orig_p']['type'] == 'integer'))
            if 'bytes_orig' in properties:
                checks.append(('bytes_orig', properties['bytes_orig']['type'] == 'long'))
            
            all_correct = all(check[1] for check in checks)
            
            if all_correct:
                self.log_test(test_name, True, f"Verified {len(checks)} field types")
            else:
                failed = [check[0] for check in checks if not check[1]]
                self.log_test(test_name, False, f"Incorrect types for: {failed}")
            
            return all_correct
        except Exception as e:
            self.log_test(test_name, False, f"Error: {str(e)}")
            return False
    
    def test_8_check_timestamp_range(self):
        """Verify timestamps are from expected date range"""
        test_name = "Timestamps are from PCAP date range (2015)"
        
        try:
            # Get min and max timestamps
            result = self.es.search(
                index='zeek-conn',
                body={
                    'size': 0,
                    'aggs': {
                        'min_ts': {'min': {'field': 'ts'}},
                        'max_ts': {'max': {'field': 'ts'}}
                    }
                }
            )
            
            if result['aggregations']['min_ts']['value'] is None:
                self.log_test(test_name, False, "No timestamp data found")
                return False
            
            min_ts = result['aggregations']['min_ts']['value']
            max_ts = result['aggregations']['max_ts']['value']
            
            # PCAP is from 2015 (March-April based on directory names)
            # Timestamps should be in that range
            # 2015-01-01: 1420070400
            # 2015-12-31: 1451520000
            # But synthetic data uses 2021-01-01: 1609459200
            
            is_2015 = min_ts >= 1420070400 and max_ts <= 1451520000
            is_synthetic = min_ts >= 1609459200
            
            import datetime
            min_date = datetime.datetime.fromtimestamp(min_ts)
            max_date = datetime.datetime.fromtimestamp(max_ts)
            
            if is_synthetic:
                self.log_test(test_name, False, 
                    f"Data is synthetic (dates: {min_date} to {max_date})")
                return False
            elif is_2015:
                self.log_test(test_name, True, 
                    f"Data from PCAP (dates: {min_date} to {max_date})")
                return True
            else:
                self.log_test(test_name, False, 
                    f"Unexpected date range: {min_date} to {max_date}")
                return False
        except Exception as e:
            self.log_test(test_name, False, f"Error: {str(e)}")
            return False
    
    def test_9_sample_data_query(self):
        """Test sample query on the data"""
        test_name = "Sample data query"
        
        try:
            # Query for HTTP traffic
            result = self.es.search(
                index='zeek-http',
                body={
                    'size': 5,
                    'query': {'match_all': {}},
                    'sort': [{'ts': 'asc'}]
                }
            )
            
            count = result['hits']['total']['value']
            if count > 0:
                self.log_test(test_name, True, f"Successfully queried {count} HTTP records")
                if result['hits']['hits']:
                    sample = result['hits']['hits'][0]['_source']
                    print(f"  → Sample fields: {list(sample.keys())[:10]}")
                return True
            else:
                self.log_test(test_name, False, "No HTTP records found")
                return False
        except Exception as e:
            self.log_test(test_name, False, f"Error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all tests and generate report"""
        print("\n" + "="*60)
        print("PCAP DATA INGESTION VALIDATION TESTS")
        print("="*60 + "\n")
        
        self.test_1_check_snort_files_are_pcaps()
        self.test_2_check_demo_pcap_exists()
        self.test_3_check_elasticsearch_connection()
        self.test_4_check_indices_exist()
        self.test_5_check_document_counts()
        self.test_6_check_data_is_from_pcap()
        self.test_7_check_field_types()
        self.test_8_check_timestamp_range()
        self.test_9_sample_data_query()
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        passed = sum(1 for r in self.results if r['passed'])
        total = len(self.results)
        
        print(f"Tests Passed: {passed}/{total}")
        print(f"Tests Failed: {total - passed}/{total}")
        
        if passed == total:
            print("\n✓ ALL TESTS PASSED - PCAP data properly ingested!")
        else:
            print("\n✗ SOME TESTS FAILED - Issues detected with PCAP ingestion")
            print("\nFailed tests:")
            for r in self.results:
                if not r['passed']:
                    print(f"  - {r['test']}: {r['message']}")
        
        print("="*60 + "\n")
        
        return passed == total

if __name__ == '__main__':
    import sys
    os.chdir('/workspaces/corelight-mcp-demo')
    tester = TestPCAPIngestion()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
