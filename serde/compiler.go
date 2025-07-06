package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"log"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

func compile(src string) []byte {
	log.SetFlags(log.Lshortfile)
	c := &compiler{}
	sts := c.getStructs(src)
	pkgName := c.file.Name.Name
	fileId := path.Join(c.pkg.ID, path.Base(src))

	f := genFileHeader(pkgName, fileId)
	for _, st := range sts {
		enc, dec := c.shouldGen(st)
		if enc {
			f.Decls = append(f.Decls, c.genEncode(st))
		}
		if dec {
			f.Decls = append(f.Decls, c.genDecode(st))
		}
	}
	return printGo(f)
}

type compiler struct {
	pkg  *packages.Package
	file *ast.File
}

// getStructs post-cond: return struct objects.
func (c *compiler) getStructs(src string) []types.Object {
	abs, err := filepath.Abs(src)
	if err != nil {
		log.Panic(err)
	}
	dir := path.Dir(src)

	mode := packages.NeedName | packages.NeedFiles
	mode |= packages.NeedImports | packages.NeedDeps
	mode |= packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	cfg := &packages.Config{
		Mode: mode,
		Dir:  dir,
	}
	pkgs, err := packages.Load(cfg, "")
	if err != nil {
		log.Panic(err)
	}
	if len(pkgs) != 1 {
		log.Panic("pkg len not 1")
	}
	pkg := pkgs[0]
	c.pkg = pkg
	info := pkg.TypesInfo

	var file *ast.File
	for _, f := range pkg.Syntax {
		tokF := pkg.Fset.File(f.FileStart)
		if abs == tokF.Name() {
			file = f
		}
	}
	if file == nil {
		log.Panic("found no files matching src. does src end in .go?")
	}
	c.file = file

	var sts []types.Object
	for _, d := range file.Decls {
		d2, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		if d2.Tok != token.TYPE {
			continue
		}
		s, ok := d2.Specs[0].(*ast.TypeSpec)
		if !ok {
			continue
		}
		_, ok = s.Type.(*ast.StructType)
		if !ok {
			continue
		}
		o, ok := info.Defs[s.Name]
		if !ok {
			log.Panic(s.Name, " is not in defs map")
		}
		_ = o.Type().Underlying().(*types.Struct)
		sts = append(sts, o)
	}
	return sts
}

func genFileHeader(pkgName, fileId string) *ast.File {
	importDecl := &ast.GenDecl{
		Tok: token.IMPORT,
		Specs: []ast.Spec{
			&ast.ImportSpec{
				Path: &ast.BasicLit{
					Kind:  token.STRING,
					Value: "\"github.com/sanjit-bhat/pav/safemarshal\"",
				},
			},
			&ast.ImportSpec{
				Path: &ast.BasicLit{
					Kind:  token.STRING,
					Value: "\"github.com/tchajed/marshal\"",
				},
			},
		},
	}
	// Hacky: pkg comment fix. Pkg starts after pkg comment.
	commPos := token.Pos(1)
	comm1 := &ast.Comment{
		Slash: commPos,
		Text:  fmt.Sprintf("// Auto-generated from spec \"%s\"", fileId),
	}
	comm2 := &ast.Comment{
		Slash: commPos,
		Text:  "// using compiler \"github.com/sanjit-bhat/pav/serde\".",
	}
	file := &ast.File{
		Doc:     &ast.CommentGroup{List: []*ast.Comment{comm1, comm2}},
		Package: commPos + 1,
		Name:    &ast.Ident{Name: pkgName},
		Decls: []ast.Decl{
			importDecl,
		},
	}
	return file
}

// shouldGen checks whether a struct has special comments to not gen some funcs.
func (c *compiler) shouldGen(o types.Object) (encode bool, decode bool) {
	encode, decode = true, true
	p, _ := astutil.PathEnclosingInterval(c.file, o.Pos(), o.Pos())
	// First two are Ident and TypeSpec.
	d := p[2].(*ast.GenDecl)
	if d.Doc == nil {
		return
	}
	for _, comm := range d.Doc.List {
		if comm.Text == "// serde: no encode needed." {
			encode = false
		}
		if comm.Text == "// serde: no decode needed." {
			decode = false
		}
	}
	return
}

func (c *compiler) genEncode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)
	funcTy := &ast.FuncType{
		Params: &ast.FieldList{List: []*ast.Field{
			{
				Names: []*ast.Ident{{Name: "b0"}},
				Type:  &ast.ArrayType{Elt: &ast.Ident{Name: "byte"}},
			},
			{
				Names: []*ast.Ident{{Name: "o"}},
				Type:  &ast.StarExpr{X: &ast.Ident{Name: name}},
			},
		}},
		Results: &ast.FieldList{List: []*ast.Field{{
			Type: &ast.ArrayType{Elt: &ast.Ident{Name: "byte"}}}},
		},
	}
	body := make([]ast.Stmt, 0)
	varDecl := &ast.DeclStmt{Decl: &ast.GenDecl{
		Tok: token.VAR,
		Specs: []ast.Spec{&ast.ValueSpec{
			Names:  []*ast.Ident{{Name: "b"}},
			Values: []ast.Expr{&ast.Ident{Name: "b0"}},
		}},
	}}
	body = append(body, varDecl)
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, c.genFieldEnc(field))
	}
	retStmt := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
		},
	}
	body = append(body, retStmt)
	return &ast.FuncDecl{
		Name: &ast.Ident{Name: fmt.Sprintf("%vEncode", name)},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func (c *compiler) genFieldEnc(field *types.Var) ast.Stmt {
	var call *ast.CallExpr
	switch fTy := field.Type().Underlying().(type) {
	case *types.Basic:
		call = c.genBasicEnc(field)
	case *types.Slice:
		call = &ast.CallExpr{
			Fun:  c.genSliceEnc(fTy, 1),
			Args: genStdFieldEncArgs(field.Name()),
		}
	case *types.Pointer:
		_ = fTy.Elem().(*types.Named).Underlying().(*types.Struct)
		call = c.genStructEnc(field)
	case *types.Map:
		call = c.genMapEnc(field)
	default:
		log.Panic("unsupported type: ", fTy)
	}
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.Ident{Name: "b"}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{call},
	}
}

func (c *compiler) genBasicEnc(field *types.Var) *ast.CallExpr {
	var fun *ast.SelectorExpr
	basic := field.Type().Underlying().(*types.Basic)
	switch basic.Kind() {
	case types.Bool:
		fun = &ast.SelectorExpr{
			X:   &ast.Ident{Name: "marshal"},
			Sel: &ast.Ident{Name: "WriteBool"},
		}
	case types.Byte:
		fun = &ast.SelectorExpr{
			X:   &ast.Ident{Name: "safemarshal"},
			Sel: &ast.Ident{Name: "WriteByte"},
		}
	case types.Uint64:
		fun = &ast.SelectorExpr{
			X:   &ast.Ident{Name: "marshal"},
			Sel: &ast.Ident{Name: "WriteInt"},
		}
	default:
		log.Panic("unsupported type: ", basic.Name())
	}
	isCst, cst := c.getConst(field.Pos())
	if isCst {
		return &ast.CallExpr{
			Fun: fun,
			Args: []ast.Expr{
				&ast.Ident{Name: "b"},
				&ast.BasicLit{Kind: token.INT, Value: cst},
			},
		}
	} else {
		return &ast.CallExpr{
			Fun:  fun,
			Args: genStdFieldEncArgs(field.Name()),
		}
	}
}

func (c *compiler) genSliceEnc(ty1 *types.Slice, depth int) ast.Expr {
	if depth > 3 {
		log.Panic("unsupported slice nesting beyond depth 3")
	}
	switch ty2 := ty1.Elem().Underlying().(type) {
	case *types.Slice:
		return c.genSliceEnc(ty2, depth+1)
	case *types.Basic:
		if ty2.Kind() != types.Byte {
			log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
		}
		return &ast.SelectorExpr{
			X:   &ast.Ident{Name: "safemarshal"},
			Sel: &ast.Ident{Name: fmt.Sprintf("WriteSlice%vD", depth)},
		}
	case *types.Pointer:
		n := ty2.Elem().(*types.Named)
		_ = n.Underlying().(*types.Struct)
		stName := n.Obj().Name()
		return &ast.Ident{Name: fmt.Sprintf("%vSlice%vDEncode", stName, depth)}
	default:
		log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
	}
	return nil
}

func (c *compiler) genStructEnc(field *types.Var) *ast.CallExpr {
	stName := field.Type().Underlying().(*types.Pointer).Elem().(*types.Named).Obj().Name()
	return &ast.CallExpr{
		Fun:  &ast.Ident{Name: fmt.Sprintf("%vEncode", stName)},
		Args: genStdFieldEncArgs(field.Name()),
	}
}

// TODO: maybe make this an abstraction that gets the handler name
// for any type that we need a compiled / user-supplied handler.
// TODO: if we took out the const feature, could maybe factor out the args
// for all these CallExpr's.
func (c *compiler) genMapEnc(field *types.Var) *ast.CallExpr {
	fTy := field.Type().Underlying()
	canon := getCanonTyName(fTy)
	return &ast.CallExpr{
		Fun:  &ast.Ident{Name: fmt.Sprintf("%vEncode", canon)},
		Args: genStdFieldEncArgs(field.Name()),
	}
}

// TODO: right now this is definitely not canonical,
// especially with nested types.
func getCanonTyName(ty1 types.Type) string {
	switch ty2 := ty1.(type) {
	case *types.Basic:
		return ty2.Name()
	case *types.Slice:
		return "Sl" + getCanonTyName(ty2.Elem().Underlying())
	case *types.Map:
		return "Map" + getCanonTyName(ty2.Key().Underlying()) + getCanonTyName(ty2.Elem().Underlying())
	case *types.Pointer:
		n := ty2.Elem().(*types.Named)
		// currently, only support pointers to structs.
		_ = n.Underlying().(*types.Struct)
		return n.Obj().Name()
	default:
		log.Panicf("unsupported ty: %s", ty2)
	}
	return ""
}

// getConst uses ast pos to check if field has special constant comment.
func (c *compiler) getConst(pos token.Pos) (isCst bool, cst string) {
	p, _ := astutil.PathEnclosingInterval(c.file, pos, pos)
	// First node is ident, then there's field.
	node := p[1].(*ast.Field)
	if node.Doc == nil {
		return false, ""
	}
	for _, comm := range node.Doc.List {
		text := comm.Text
		text, found0 := strings.CutPrefix(text, "// serde: invariant: const ")
		text, found1 := strings.CutSuffix(text, ".")
		if found0 && found1 {
			isCst = true
			cst = text
		}
	}
	return
}

func genStdFieldEncArgs(name string) []ast.Expr {
	return []ast.Expr{
		&ast.Ident{Name: "b"},
		&ast.SelectorExpr{
			X:   &ast.Ident{Name: "o"},
			Sel: &ast.Ident{Name: name},
		},
	}
}

func (c *compiler) genDecode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Params: &ast.FieldList{
			List: []*ast.Field{{
				Names: []*ast.Ident{{Name: "b0"}},
				Type:  &ast.ArrayType{Elt: &ast.Ident{Name: "byte"}},
			}},
		},
		Results: &ast.FieldList{
			List: []*ast.Field{
				{Type: &ast.StarExpr{X: &ast.Ident{Name: name}}},
				{Type: &ast.ArrayType{Elt: &ast.Ident{Name: "byte"}}},
				{Type: &ast.Ident{Name: "bool"}},
			},
		},
	}
	body := []ast.Stmt{}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, c.genFieldDec(field, i)...)
	}
	var fieldsInit []ast.Expr
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		init := &ast.KeyValueExpr{
			Key:   &ast.Ident{Name: field.Name()},
			Value: &ast.Ident{Name: fmt.Sprintf("a%v", i+1)},
		}
		fieldsInit = append(fieldsInit, init)
	}
	objInit := &ast.UnaryExpr{
		Op: token.AND,
		X: &ast.CompositeLit{
			Type: &ast.Ident{Name: name},
			Elts: fieldsInit,
		},
	}
	ret := &ast.ReturnStmt{
		Results: []ast.Expr{
			objInit,
			&ast.Ident{Name: fmt.Sprintf("b%v", st.NumFields())},
			&ast.Ident{Name: "false"},
		},
	}
	body = append(body, ret)
	return &ast.FuncDecl{
		Name: &ast.Ident{Name: fmt.Sprintf("%vDecode", name)},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func (c *compiler) genFieldDec(field *types.Var, fieldNum int) []ast.Stmt {
	var call *ast.CallExpr
	oldB := fmt.Sprintf("b%v", fieldNum)
	switch fTy := field.Type().Underlying().(type) {
	case *types.Basic:
		call = c.genBasicDec(field, oldB)
	case *types.Slice:
		call = &ast.CallExpr{
			Fun:  c.genSliceDec(fTy, 1),
			Args: []ast.Expr{&ast.Ident{Name: oldB}},
		}
	case *types.Pointer:
		n := fTy.Elem().(*types.Named)
		_ = n.Underlying().(*types.Struct)
		call = c.genStructDec(n.Obj().Name(), oldB)
	case *types.Map:
		call = c.genMapDec(field, oldB)
	default:
		log.Panic("unsupported type: ", fTy)
	}
	newX := fmt.Sprintf("a%v", fieldNum+1)
	newB := fmt.Sprintf("b%v", fieldNum+1)
	newErr := fmt.Sprintf("err%v", fieldNum+1)
	assign := &ast.AssignStmt{
		Lhs: []ast.Expr{
			&ast.Ident{Name: newX},
			&ast.Ident{Name: newB},
			&ast.Ident{Name: newErr},
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{call},
	}
	err := &ast.IfStmt{
		Cond: &ast.Ident{Name: newErr},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ReturnStmt{
				Results: []ast.Expr{
					&ast.Ident{Name: "nil"},
					&ast.Ident{Name: "nil"},
					&ast.Ident{Name: "true"},
				},
			},
		}},
	}
	return []ast.Stmt{assign, err}
}

func (c *compiler) genBasicDec(field *types.Var, inBytsId string) *ast.CallExpr {
	var cstFuncMod string
	var args []ast.Expr
	isCst, cst := c.getConst(field.Pos())
	if isCst {
		cstFuncMod = "Const"
		args = []ast.Expr{
			&ast.Ident{Name: inBytsId},
			&ast.BasicLit{Kind: token.INT, Value: cst},
		}
	} else {
		args = []ast.Expr{&ast.Ident{Name: inBytsId}}
	}

	var fun *ast.SelectorExpr
	basic := field.Type().Underlying().(*types.Basic)
	switch basic.Kind() {
	case types.Bool:
		fun = &ast.SelectorExpr{
			X:   &ast.Ident{Name: "safemarshal"},
			Sel: &ast.Ident{Name: fmt.Sprintf("Read%sBool", cstFuncMod)},
		}
	case types.Byte:
		fun = &ast.SelectorExpr{
			X:   &ast.Ident{Name: "safemarshal"},
			Sel: &ast.Ident{Name: fmt.Sprintf("Read%sByte", cstFuncMod)},
		}
	case types.Uint64:
		fun = &ast.SelectorExpr{
			X:   &ast.Ident{Name: "safemarshal"},
			Sel: &ast.Ident{Name: fmt.Sprintf("Read%sInt", cstFuncMod)},
		}
	default:
		log.Panic("unsupported type: ", basic.Name())
	}

	return &ast.CallExpr{
		Fun:  fun,
		Args: args,
	}
}

func (c *compiler) genSliceDec(ty1 *types.Slice, depth int) ast.Expr {
	if depth > 3 {
		log.Panic("unsupported slice nesting beyond depth 3")
	}
	switch ty2 := ty1.Elem().Underlying().(type) {
	case *types.Slice:
		return c.genSliceDec(ty2, depth+1)
	case *types.Basic:
		if ty2.Kind() != types.Byte {
			log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
		}
		return &ast.SelectorExpr{
			X:   &ast.Ident{Name: "safemarshal"},
			Sel: &ast.Ident{Name: fmt.Sprintf("ReadSlice%vD", depth)},
		}
	case *types.Pointer:
		n := ty2.Elem().(*types.Named)
		_ = n.Underlying().(*types.Struct)
		stName := n.Obj().Name()
		return &ast.Ident{Name: fmt.Sprintf("%vSlice%vDDecode", stName, depth)}
	default:
		log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
	}
	return nil
}

func (c *compiler) genStructDec(stName string, inBytsId string) *ast.CallExpr {
	return &ast.CallExpr{
		Fun:  &ast.Ident{Name: fmt.Sprintf("%vDecode", stName)},
		Args: []ast.Expr{&ast.Ident{Name: inBytsId}},
	}
}

func (c *compiler) genMapDec(field *types.Var, inBytsId string) *ast.CallExpr {
	fTy := field.Type().Underlying()
	canon := getCanonTyName(fTy)
	return &ast.CallExpr{
		Fun:  &ast.Ident{Name: fmt.Sprintf("%vDecode", canon)},
		Args: []ast.Expr{&ast.Ident{Name: inBytsId}},
	}
}

func printGo(n any) []byte {
	fset := token.NewFileSet()
	// Hacky: pkg comment fix. Range big enough to fit both specified pos's.
	fset.AddFile("out.go", 1, 1)
	buf := new(bytes.Buffer)
	err := format.Node(buf, fset, n)
	if err != nil {
		log.Panic(err)
	}
	return buf.Bytes()
}
