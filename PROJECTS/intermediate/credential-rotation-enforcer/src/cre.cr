# ===================
# ©AngelaMos | 2026
# cre.cr
# ===================

require "./cre/version"

module CRE
  def self.main(argv : Array(String)) : Int32
    0
  end
end

if PROGRAM_NAME.includes?("cre")
  exit CRE.main(ARGV)
end
