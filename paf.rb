#!/usr/bin/env ruby
# frozen_string_literal: true

require 'faraday'
require 'differ'
require 'differ/string'

class Differ::Diff
  def changes
    @raw.reject { |e| e.is_a? String }
  end
end

class Fuzzer
  def initialize(url)
    @url = url
  end

  def max_query_size
    (0..65_535).bsearch { |n| q('_' * n)[0] == 414 }
  end

  def max_params_count
    (0..65_535).bsearch { |n| q((0..n).map{|p|"__#{p}="}.join('&'))[0] > 399 }
  end

  def fuzz_params(max_qs, max_pc)
    stages = {
      'Dict': File.readlines('./par.txt').map {|ln| ln.strip},
      'a..z': ('a'..'z'),
      'aa..zz': ('aa'..'zz'),
      'aaa..zzz': ('aaa'..'zzz'),
      'aaaa..zzzz': ('aaaa'..'zzzz')
    }

    ok_s, ok_body = q

    stages.each do |name, range|
      vals = range.to_a
      var_s = range.first.size
      item_size = var_s + 2
      item_size = range.max_by(&:size).size + 2 if range.is_a? Array
      items_per_query = [max_pc, (max_qs / item_size).floor].min

      STDERR.print "[*] #{name}"

      vals.each_slice(items_per_query) do |part|
        loop do
          param = part.bsearch do |v|
            params = part[..part.index(v)].map { |p| "#{p}=" }.join('&')
            s, body = q(params)
            diff = (body - ok_body).changes
            r = s != ok_s || diff.size > 0

            STDERR.print "."
            # warn "\n[i] code: #{s}, diff count: #{diff.size}" if r
            r
          end
          break unless param

          puts "\n[+] #{param}"

          part = part.drop_while { |v| v != param }[1..]
          break unless part && part.any?
        end
      end
      warn
    end
  end

  def fuzz
    warn '[*] Determining max query size...'
    max_qs = max_query_size
    warn "[i] Max query size: #{max_qs}"

    warn '[*] Determining max params count...'
    max_pc = max_params_count
    warn "[i] Max params count: #{max_pc}"

    fuzz_params(max_qs, max_pc)
  end

  def q(params = '')
    res = Faraday.get("#{@url}?#{params}", params: params)
    [res.status, res.body]
  end
end

f = Fuzzer.new ARGV[0]
f.fuzz
