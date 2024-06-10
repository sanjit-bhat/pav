package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
	"log"
	"path"
	"path/filepath"
	"strings"
)

type compiler struct {
	pkg  *packages.Package
	file *ast.File
}

// getStructs post-cond: return struct objects.
func (c *compiler) getStructs(src string) []types.Object {
	abs, err := filepath.Abs(src)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	if len(pkgs) != 1 {
		log.Fatal("pkg len not 1")
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
		log.Fatal("found no files matching src. does src end in .go?")
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
			log.Fatalf("%s is not in defs map", s.Name)
		}
		_ = o.Type().Underlying().(*types.Struct)
		sts = append(sts, o)
	}
	return sts
}

func genRcvr(name string) *ast.FieldList {
	return &ast.FieldList{
		List: []*ast.Field{{
			Names: []*ast.Ident{{Name: "o"}},
			Type:  &ast.StarExpr{X: &ast.Ident{Name: name}},
		}},
	}
}

func (c *compiler) getFixedLen(f *types.Var) (isFixed bool, length string) {
	p, _ := astutil.PathEnclosingInterval(c.file, f.Pos(), f.Pos())
	// First node is ident, then there's field.
	node := p[1].(*ast.Field)
	if node.Doc == nil {
		return false, ""
	}
	comm := node.Doc.List[0].Text
	comm = strings.TrimPrefix(comm, "// Invariant: len ")
	comm = strings.TrimRight(comm, ".")
	return true, comm
}

func (c *compiler) genFieldWrite(field *types.Var) ast.Stmt {
	name := field.Name()
	var fun *ast.SelectorExpr
	switch fTy := field.Type().(type) {
	case *types.Slice:
		basic := fTy.Elem().(*types.Basic)
		if basic.Kind() != types.Byte {
			log.Fatal("unsupported slice elem ty: ", basic.Name())
		}
		isFixed, _ := c.getFixedLen(field)
		if isFixed {
			fun = &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshal"},
				Sel: &ast.Ident{Name: "WriteBytes"},
			}
		} else {
			fun = &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshalutil"},
				Sel: &ast.Ident{Name: "WriteSlice1D"},
			}
		}
	case *types.Basic:
		switch fTy.Kind() {
		case types.Uint64:
			fun = &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshal"},
				Sel: &ast.Ident{Name: "WriteInt"},
			}
		case types.Bool:
			fun = &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshalutil"},
				Sel: &ast.Ident{Name: "WriteBool"},
			}
		default:
			log.Fatal("unsupported type: ", fTy.Name())
		}
	default:
		log.Fatal("unsupported type: ", fTy)
	}
	call := &ast.CallExpr{
		Fun: fun,
		Args: []ast.Expr{
			&ast.Ident{Name: "b"},
			&ast.SelectorExpr{
				X:   &ast.Ident{Name: "o"},
				Sel: &ast.Ident{Name: name},
			},
		},
	}
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.Ident{Name: "b"}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{call},
	}
}

func (c *compiler) genEncode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Results: &ast.FieldList{
			List: []*ast.Field{{
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
			}},
		},
	}
	callMake := &ast.CallExpr{
		Fun: &ast.Ident{Name: "make"},
		Args: []ast.Expr{
			&ast.ArrayType{
				Elt: &ast.Ident{Name: "byte"},
			},
			&ast.BasicLit{Kind: token.INT, Value: "0"},
		},
	}
	makeByteSl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{{Name: "b"}},
					Values: []ast.Expr{callMake},
				},
			},
		},
	}
	body := []ast.Stmt{makeByteSl}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, c.genFieldWrite(field))
	}
	retStmt := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
		},
	}
	body = append(body, retStmt)
	return &ast.FuncDecl{
		Recv: genRcvr(name),
		Name: &ast.Ident{Name: "encode"},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func (c *compiler) genFieldRead(field *types.Var) []ast.Stmt {
	name := field.Name()
	var call *ast.CallExpr
	switch fTy := field.Type().(type) {
	case *types.Slice:
		basic := fTy.Elem().(*types.Basic)
		if basic.Kind() != types.Byte {
			log.Fatal("unsupported slice elem ty: ", basic.Name())
		}
		isFixed, length := c.getFixedLen(field)
		if isFixed {
			call = &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "marshalutil"},
					Sel: &ast.Ident{Name: "SafeReadBytes"},
				},
				Args: []ast.Expr{
					&ast.Ident{Name: "b"},
					&ast.BasicLit{Kind: token.INT, Value: length},
				},
			}
		} else {
			call = &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "marshalutil"},
					Sel: &ast.Ident{Name: "ReadSlice1D"},
				},
				Args: []ast.Expr{&ast.Ident{Name: "b"}},
			}
		}
	case *types.Basic:
		switch fTy.Kind() {
		case types.Uint64:
			call = &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "marshalutil"},
					Sel: &ast.Ident{Name: "SafeReadInt"},
				},
				Args: []ast.Expr{&ast.Ident{Name: "b"}},
			}
		case types.Bool:
			call = &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "marshalutil"},
					Sel: &ast.Ident{Name: "ReadBool"},
				},
				Args: []ast.Expr{&ast.Ident{Name: "b"}},
			}
		default:
			log.Fatal("unsupported type: ", fTy.Name())
		}
	default:
		log.Fatal("unsupported type: ", fTy)
	}
	assign := &ast.AssignStmt{
		Lhs: []ast.Expr{
			&ast.Ident{Name: name},
			&ast.Ident{Name: "b"},
			&ast.Ident{Name: "err"},
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{call},
	}
	err := &ast.IfStmt{
		Cond: &ast.Ident{Name: "err"},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ReturnStmt{
				Results: []ast.Expr{
					&ast.Ident{Name: "nil"},
					&ast.Ident{Name: "err"},
				},
			},
		}},
	}
	return []ast.Stmt{assign, err}
}

func genFieldAssign(field *types.Var) ast.Stmt {
	name := field.Name()
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.SelectorExpr{
			X:   &ast.Ident{Name: "o"},
			Sel: &ast.Ident{Name: name},
		}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{&ast.Ident{Name: name}},
	}
}

func (c *compiler) genDecode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Params: &ast.FieldList{
			List: []*ast.Field{{
				Names: []*ast.Ident{{Name: "b0"}},
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
			}},
		},
		Results: &ast.FieldList{
			List: []*ast.Field{
				{Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				}},
				{Type: &ast.Ident{Name: "errorTy"}},
			},
		},
	}
	varDecl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{{Name: "b"}},
					Values: []ast.Expr{&ast.Ident{Name: "b0"}},
				},
			},
		},
	}
	ret := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
			&ast.Ident{Name: "errNone"},
		},
	}
	body := []ast.Stmt{varDecl}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, c.genFieldRead(field)...)
	}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, genFieldAssign(field))
	}
	body = append(body, ret)
	return &ast.FuncDecl{
		Recv: genRcvr(name),
		Name: &ast.Ident{Name: "decode"},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func genFileHeader(pkgName, fileId string) *ast.File {
	importDecl := &ast.GenDecl{
		Tok: token.IMPORT,
		Specs: []ast.Spec{
			&ast.ImportSpec{
				Path: &ast.BasicLit{
					Kind:  token.STRING,
					Value: "\"github.com/mit-pdos/pav/marshalutil\"",
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
	errTypeDecl := &ast.GenDecl{
		Tok: token.TYPE,
		Specs: []ast.Spec{
			&ast.TypeSpec{
				Name:   &ast.Ident{Name: "errorTy"},
				Assign: 1,
				Type:   &ast.Ident{Name: "bool"},
			},
		},
	}
	constErrDecl := &ast.GenDecl{
		Tok: token.CONST,
		Specs: []ast.Spec{
			&ast.ValueSpec{
				Names:  []*ast.Ident{{Name: "errNone"}},
				Type:   &ast.Ident{Name: "errorTy"},
				Values: []ast.Expr{&ast.Ident{Name: "false"}},
			},
			&ast.ValueSpec{
				Names:  []*ast.Ident{{Name: "errSome"}},
				Type:   &ast.Ident{Name: "errorTy"},
				Values: []ast.Expr{&ast.Ident{Name: "true"}},
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
		Text:  "// using compiler \"github.com/mit-pdos/pav/rpc\".",
	}
	file := &ast.File{
		Doc:     &ast.CommentGroup{List: []*ast.Comment{comm1, comm2}},
		Package: commPos + 1,
		Name:    &ast.Ident{Name: pkgName},
		Decls: []ast.Decl{
			importDecl,
			errTypeDecl,
			constErrDecl,
		},
	}
	return file
}

func printGo(n any) []byte {
	fset := token.NewFileSet()
	// Hacky: pkg comment fix. Range big enough to fit both specified pos's.
	fset.AddFile("out.go", 1, 1)
	buf := new(bytes.Buffer)
	err := format.Node(buf, fset, n)
	if err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

// printAst when developing. See AST of golden files.
func printAst(src []byte) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		log.Fatal(err)
	}
	res := new(bytes.Buffer)
	ast.Fprint(res, fset, f, ast.NotNilFilter)
	return res.Bytes()
}

func compile(src string) []byte {
	log.SetFlags(log.Lshortfile)
	c := &compiler{}
	sts := c.getStructs(src)
	pkgName := c.file.Name.Name
	fileId := path.Join(c.pkg.ID, path.Base(src))

	f := genFileHeader(pkgName, fileId)
	for _, st := range sts {
		enc := c.genEncode(st)
		dec := c.genDecode(st)
		f.Decls = append(f.Decls, enc, dec)
	}
	return printGo(f)
}
